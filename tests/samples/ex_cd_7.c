/*
 * Usage: ./program <event_file>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Event types
typedef enum {
    EVENT_ALLOCATE,
    EVENT_PROCESS,
    EVENT_CLEANUP,
    EVENT_FINALIZE,
    EVENT_UNKNOWN
} event_type_t;

// Event buffer management
typedef struct {
    char *event_buffer;
    char *backup_buffer;
    int buffer_active;
    int backup_active;
} event_manager_t;

event_manager_t g_event_mgr = {NULL, NULL, 0, 0};

void handle_finalize_event(char *event_data) {
    printf("Handling finalize event: %s\n", event_data);
    
    
    if (g_event_mgr.buffer_active && g_event_mgr.event_buffer) {
        printf("Finalizing with event buffer: %s\n", g_event_mgr.event_buffer); 
        strcat(g_event_mgr.event_buffer, "_FINALIZED");  
    }
    
    if (g_event_mgr.backup_active && g_event_mgr.backup_buffer) {
        printf("Finalizing with backup buffer: %s\n", g_event_mgr.backup_buffer); 
        strcat(g_event_mgr.backup_buffer, "_BACKUP_FINALIZED");  
    }
}

// Function that handles cleanup events
void handle_cleanup_event(char *event_data) {
    printf("Handling cleanup event: %s\n", event_data);
    
    if (strstr(event_data, "PRIMARY") && g_event_mgr.event_buffer) {
        printf("Cleaning up primary event buffer\n");
        free(g_event_mgr.event_buffer);
        
    }
    
    if (strstr(event_data, "BACKUP") && g_event_mgr.backup_buffer) {
        printf("Cleaning up backup buffer\n");
        free(g_event_mgr.backup_buffer);
        
    }
    
    if (strstr(event_data, "ALL")) {
        if (g_event_mgr.event_buffer) {
            printf("Cleaning up all buffers - primary\n");
            free(g_event_mgr.event_buffer);
        }
        if (g_event_mgr.backup_buffer) {
            printf("Cleaning up all buffers - backup\n");
            free(g_event_mgr.backup_buffer);
        }
        
    }
}


void handle_process_event(char *event_data) {
    printf("Handling process event: %s\n", event_data);
    
    if (g_event_mgr.buffer_active && g_event_mgr.event_buffer) {
        strcat(g_event_mgr.event_buffer, "_PROCESSED");
        printf("Event buffer processed: %s\n", g_event_mgr.event_buffer);
    }
    
    if (g_event_mgr.backup_active && g_event_mgr.backup_buffer) {
        strcat(g_event_mgr.backup_buffer, "_BACKUP_PROCESSED");
        printf("Backup buffer processed: %s\n", g_event_mgr.backup_buffer);
    }
}


void handle_allocate_event(char *event_data) {
    printf("Handling allocate event: %s\n", event_data);
    
    if (strstr(event_data, "PRIMARY")) {
        g_event_mgr.event_buffer = (char *)malloc(256);
        if (g_event_mgr.event_buffer) {
            strcpy(g_event_mgr.event_buffer, "EVENT_DATA");
            g_event_mgr.buffer_active = 1;
            printf("Primary event buffer allocated\n");
        }
    }
    
    if (strstr(event_data, "BACKUP")) {
        g_event_mgr.backup_buffer = (char *)malloc(256);
        if (g_event_mgr.backup_buffer) {
            strcpy(g_event_mgr.backup_buffer, "BACKUP_DATA");
            g_event_mgr.backup_active = 1;
            printf("Backup buffer allocated\n");
        }
    }
}


event_type_t parse_event_type(char *event_str) {
    if (strstr(event_str, "ALLOCATE:")) return EVENT_ALLOCATE;
    if (strstr(event_str, "PROCESS:")) return EVENT_PROCESS;
    if (strstr(event_str, "CLEANUP:")) return EVENT_CLEANUP;
    if (strstr(event_str, "FINALIZE:")) return EVENT_FINALIZE;
    return EVENT_UNKNOWN;
}


void dispatch_event(char *event_line) {
    event_type_t event_type = parse_event_type(event_line);
    char *event_data = strchr(event_line, ':');
    
    if (event_data) {
        event_data++;  // Skip the ':'
        
        switch (event_type) {
            case EVENT_ALLOCATE:
                handle_allocate_event(event_data);
                break;
            case EVENT_PROCESS:
                handle_process_event(event_data);
                break;
            case EVENT_CLEANUP:
                handle_cleanup_event(event_data);
                break;
            case EVENT_FINALIZE:
                handle_finalize_event(event_data);
                break;
            default:
                printf("Unknown event type\n");
                break;
        }
    }
}


int read_event_file(const char *filename) {
    FILE *file;
    char event_line[256];
    
    file = fopen(filename, "r");
    if (!file) {
        printf("Error opening file: %s\n", filename);
        return -1;
    }
    
    printf("Reading event file: %s\n", filename);
    
    // Initialize event manager
    g_event_mgr.event_buffer = NULL;
    g_event_mgr.backup_buffer = NULL;
    g_event_mgr.buffer_active = 0;
    g_event_mgr.backup_active = 0;
    
    // Process events from file
    while (fgets(event_line, sizeof(event_line), file)) {
        event_line[strcspn(event_line, "\n")] = 0;
        printf("Processing event: %s\n", event_line);
        dispatch_event(event_line);
    }
    
    fclose(file);
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <event_file>\n", argv[0]);
        return -1;
    }
    
    return read_event_file(argv[1]);
}