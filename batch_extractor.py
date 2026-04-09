"""
Batch LLM Fact Extractor — Uses Anthropic Message Batches API for 50% cost reduction.

Submits all function extraction requests as a single batch, polls for completion,
then parses results into Fact objects. No rate limit issues, no retry logic needed.

Usage:
    # From run_pipeline.py with --batch flag
    # Or standalone:
    python batch_extractor.py submit <c_file1> <c_file2> ...
    python batch_extractor.py poll <batch_id>
    python batch_extractor.py results <batch_id> <output_dir>
"""

import json
import os
import sys
import time
from pathlib import Path

import anthropic
from anthropic.types.message_create_params import MessageCreateParamsNonStreaming
from anthropic.types.messages.batch_create_params import Request

from fact_schema import Fact, FactKind, write_facts

# Reuse the same prompt and parsing from llm_extractor
_PROMPT_PATH = Path(__file__).parent / "prompts" / "fact_extraction.md"
_SYSTEM_PROMPT = _PROMPT_PATH.read_text() if _PROMPT_PATH.exists() else ""
_KIND_MAP = {k.value: k for k in FactKind}


def _get_client() -> anthropic.Anthropic:
    """Create Anthropic client from env."""
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        raise ValueError("ANTHROPIC_API_KEY not set")
    return anthropic.Anthropic(api_key=api_key)


def _model_name() -> str:
    """Get model name, stripping litellm prefix."""
    model = os.environ.get("MODEL_NAME", "anthropic/claude-sonnet-4-6")
    # Anthropic SDK uses bare model names (no "anthropic/" prefix)
    if model.startswith("anthropic/"):
        model = model[len("anthropic/"):]
    return model


def _estimate_max_tokens(source: str) -> int:
    line_count = source.count('\n') + 1
    if line_count > 150:
        return 32000
    if line_count > 50:
        return 16384
    return 8192


def prepare_batch_requests(func_sources: list[dict]) -> list[Request]:
    """Convert function sources into batch request objects.

    Args:
        func_sources: List of dicts with keys: name, source, file_path
            Each represents one function to extract facts from.

    Returns:
        List of anthropic Request objects ready for batch submission.
    """
    model = _model_name()
    requests = []

    for fs in func_sources:
        func_name = fs["name"]
        source = fs["source"]
        file_path = fs.get("file_path", "<unknown>")
        file_stem = fs.get("file_stem", "unknown")

        max_tokens = _estimate_max_tokens(source)
        line_count = source.count('\n') + 1

        size_hint = ""
        if line_count > 100:
            size_hint = (
                f" The function is {line_count} lines long. "
                "Extract ALL facts thoroughly — do not skip any section."
            )

        user_msg = (
            f"Extract Datalog facts from this C function `{func_name}` "
            f"in file `{file_path}`.{size_hint}"
            f"\n\n```c\n{source}\n```"
        )

        # custom_id encodes file_stem--func_name for routing results back
        custom_id = f"{file_stem}--{func_name}"

        requests.append(
            Request(
                custom_id=custom_id,
                params=MessageCreateParamsNonStreaming(
                    model=model,
                    max_tokens=max_tokens,
                    temperature=0.0,
                    system=_SYSTEM_PROMPT,
                    messages=[{"role": "user", "content": user_msg}],
                ),
            )
        )

    return requests


def submit_batch(requests: list[Request]) -> str:
    """Submit a batch of requests. Returns batch_id."""
    client = _get_client()
    batch = client.messages.batches.create(requests=requests)
    print(f"  Batch submitted: {batch.id}")
    print(f"    Requests: {len(requests)}")
    print(f"    Status: {batch.processing_status}")
    return batch.id


def poll_batch(batch_id: str, poll_interval: int = 10, timeout: int = 3600) -> dict:
    """Poll until batch completes. Returns batch status dict."""
    client = _get_client()
    start = time.time()

    while True:
        batch = client.messages.batches.retrieve(batch_id)
        elapsed = time.time() - start

        counts = batch.request_counts
        total = counts.processing + counts.succeeded + counts.errored + counts.canceled + counts.expired
        done = counts.succeeded + counts.errored + counts.canceled + counts.expired

        print(f"\r  [{elapsed:.0f}s] {batch.processing_status}: "
              f"{counts.succeeded} done, {counts.processing} processing, "
              f"{counts.errored} errors (of {total})",
              end="", flush=True)

        if batch.processing_status == "ended":
            print()  # newline
            return {
                "batch_id": batch_id,
                "status": "ended",
                "succeeded": counts.succeeded,
                "errored": counts.errored,
                "expired": counts.expired,
                "elapsed_s": round(elapsed, 1),
            }

        if elapsed > timeout:
            print(f"\n  [WARN] Timeout after {timeout}s")
            return {
                "batch_id": batch_id,
                "status": "timeout",
                "succeeded": counts.succeeded,
                "errored": counts.errored,
                "elapsed_s": round(elapsed, 1),
            }

        time.sleep(poll_interval)


def retrieve_results(batch_id: str) -> dict[str, list[Fact]]:
    """Retrieve batch results and parse into facts, grouped by file_stem.

    Returns:
        Dict mapping file_stem -> list of Fact objects.
    """
    client = _get_client()
    results_by_file: dict[str, list[Fact]] = {}
    total_facts = 0
    errors = 0

    for result in client.messages.batches.results(batch_id):
        custom_id = result.custom_id
        # Parse custom_id = "file_stem--func_name"
        if "--" in custom_id:
            file_stem, func_name = custom_id.split("--", 1)
        else:
            file_stem, func_name = "unknown", custom_id

        if result.result.type == "succeeded":
            # Extract text from response
            message = result.result.message
            raw_text = ""
            for block in message.content:
                if hasattr(block, "text"):
                    raw_text += block.text

            facts = _parse_response(raw_text, func_name)

            if file_stem not in results_by_file:
                results_by_file[file_stem] = []
            results_by_file[file_stem].extend(facts)

            tokens_in = message.usage.input_tokens if message.usage else 0
            tokens_out = message.usage.output_tokens if message.usage else 0
            print(f"    {custom_id}: {len(facts)} facts "
                  f"({tokens_in}+{tokens_out} tokens)")
            total_facts += len(facts)
        else:
            error_type = result.result.type
            print(f"    {custom_id}: {error_type}")
            errors += 1

    print(f"  Total: {total_facts} facts, {errors} errors")
    return results_by_file


def write_batch_results(results_by_file: dict[str, list[Fact]],
                        work_dir: Path) -> dict[str, int]:
    """Write batch results to per-file facts directories.

    Args:
        results_by_file: Dict from retrieve_results()
        work_dir: Base work directory (e.g., eval/results/pipeline_work/)

    Returns:
        Dict mapping file_stem -> fact count.
    """
    stats = {}
    for file_stem, facts in results_by_file.items():
        facts_dir = work_dir / file_stem / "facts"
        facts_dir.mkdir(parents=True, exist_ok=True)

        # Clear stale facts
        for f in facts_dir.glob("*.facts"):
            f.unlink()

        if facts:
            write_facts(facts, str(facts_dir))
        stats[file_stem] = len(facts)
        print(f"    {file_stem}: {len(facts)} facts → {facts_dir}")

    return stats


def _parse_response(raw_json: str, func_name: str) -> list[Fact]:
    """Parse LLM JSON response into Fact objects (shared with llm_extractor)."""
    text = raw_json.strip()
    if text.startswith("```"):
        lines = text.split('\n')
        lines = lines[1:]
        if lines and lines[-1].strip().startswith("```"):
            lines = lines[:-1]
        text = '\n'.join(lines)

    try:
        data = json.loads(text)
    except json.JSONDecodeError as e:
        print(f"  [ERROR] JSON parse failed for {func_name}: {e}")
        return []

    facts_list = data.get("facts", [])
    if not isinstance(facts_list, list):
        return []

    _META_KEYS = {"kind", "func", "addr", "fields"}
    facts = []
    for item in facts_list:
        kind_str = item.get("kind", "")
        kind = _KIND_MAP.get(kind_str)
        if not kind:
            continue

        func = item.get("func", func_name)
        addr = item.get("addr", 0)
        fields = item.get("fields", {})

        extra = {k: v for k, v in item.items() if k not in _META_KEYS}
        if extra and not fields:
            fields = extra
        elif extra:
            merged = dict(extra)
            merged.update(fields)
            fields = merged

        if isinstance(addr, str):
            try:
                addr = int(addr)
            except ValueError:
                addr = 0

        facts.append(Fact(kind=kind, func=func, addr=addr, fields=fields))

    return facts


# ── CLI ─────────────────────────────────────────────────────────────────────

def _load_env():
    env_path = Path(__file__).parent / ".env"
    if env_path.exists():
        for line in env_path.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, _, val = line.partition("=")
                os.environ[key.strip()] = val.strip().strip('"')


if __name__ == "__main__":
    _load_env()

    if len(sys.argv) < 2:
        print("Usage:")
        print("  python batch_extractor.py submit <c_file1> [c_file2] ...  — submit batch")
        print("  python batch_extractor.py poll <batch_id>                 — poll status")
        print("  python batch_extractor.py results <batch_id> [output_dir] — retrieve results")
        sys.exit(1)

    cmd = sys.argv[1]

    if cmd == "submit":
        from tree_sitter_nav import enumerate_functions, get_function_with_lines
        import tempfile, shutil

        c_files = [Path(f) for f in sys.argv[2:]]
        all_requests = []

        for c_file in c_files:
            print(f"\nPreparing: {c_file.name}")
            # Enumerate functions via tree-sitter
            with tempfile.TemporaryDirectory() as tmpdir:
                tmp_file = Path(tmpdir) / c_file.name
                shutil.copy2(c_file, tmp_file)
                funcs = enumerate_functions(tmpdir)

            for fi in funcs:
                result = get_function_with_lines(str(c_file), fi.name)
                if result:
                    numbered_source, start_line = result
                    all_requests.append({
                        "name": fi.name,
                        "source": numbered_source,
                        "file_path": str(c_file),
                        "file_stem": c_file.stem,
                    })

        print(f"\nTotal: {len(all_requests)} functions from {len(c_files)} files")
        requests = prepare_batch_requests(all_requests)
        batch_id = submit_batch(requests)
        print(f"\nBatch ID: {batch_id}")
        print("Run: python batch_extractor.py poll " + batch_id)

    elif cmd == "poll":
        batch_id = sys.argv[2]
        status = poll_batch(batch_id)
        print(json.dumps(status, indent=2))

    elif cmd == "results":
        batch_id = sys.argv[2]
        output_dir = Path(sys.argv[3]) if len(sys.argv) > 3 else Path("batch_results")
        output_dir.mkdir(parents=True, exist_ok=True)

        results = retrieve_results(batch_id)
        write_batch_results(results, output_dir)

    else:
        print(f"Unknown command: {cmd}")
        sys.exit(1)
