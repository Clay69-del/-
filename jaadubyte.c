#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <jansson.h>  // JSON parsing library
#include <ctype.h>    // For case-insensitive comparison
#include <dirent.h>   // For directory processing
#include <unistd.h>   // For getopt
#include <getopt.h>   // For optarg, optind
#include <sys/stat.h> // For checking file/directory

#define MAX_MAGIC_BYTES 16
#define MAX_FILE_TYPE 32
#define LOG_DEBUG 0
#define LOG_INFO 1
#define LOG_ERROR 2

typedef struct
{
    char file_type[MAX_FILE_TYPE];
    uint8_t magic_bytes[MAX_MAGIC_BYTES];
    size_t magic_length;
    size_t offset; // Offset for matching
} MagicBytes;

void log_message(int level, const char *format, ...)
{
    const char *level_str;
    switch (level)
    {
    case LOG_DEBUG:
        level_str = "DEBUG";
        break;
    case LOG_INFO:
        level_str = "INFO";
        break;
    case LOG_ERROR:
        level_str = "ERROR";
        break;
    default:
        level_str = "LOG";
        break;
    }

    va_list args;
    va_start(args, format);
    fprintf(stderr, "[%s] ", level_str);
    vfprintf(stderr, format, args);
    fprintf(stderr, "\n");
    va_end(args);
}

MagicBytes *load_magic_bytes(const char *filename, size_t *count)
{
    json_error_t error;
    json_t *root = json_load_file(filename, 0, &error);
    if (!root)
    {
        log_message(LOG_ERROR, "Could not parse JSON file %s: %s", filename, error.text);
        exit(EXIT_FAILURE);
    }

    if (!json_is_object(root))
    {
        log_message(LOG_ERROR, "JSON root is not an object");
        json_decref(root);
        exit(EXIT_FAILURE);
    }

    size_t array_size = 0;

    // Calculate total size needed for MagicBytes
    const char *category_key;
    json_t *category_value;
    json_object_foreach(root, category_key, category_value)
    {
        if (!json_is_object(category_value))
        {
            log_message(LOG_ERROR, "Category %s is not an object", category_key);
            continue;
        }

        const char *file_type_key;
        json_t *magic_value;
        json_object_foreach(category_value, file_type_key, magic_value)
        {
            if (json_is_string(magic_value))
            {
                array_size++;
            }
        }
    }

    MagicBytes *magic_list = malloc(array_size * sizeof(MagicBytes));
    size_t index = 0;

    // Load data into MagicBytes array
    json_object_foreach(root, category_key, category_value)
    {
        if (!json_is_object(category_value))
        {
            continue;
        }

        const char *file_type_key;
        json_t *magic_value;
        json_object_foreach(category_value, file_type_key, magic_value)
        {
            if (!json_is_string(magic_value))
            {
                log_message(LOG_ERROR, "Magic bytes for %s in category %s are not a string", file_type_key, category_key);
                continue;
            }

            strncpy(magic_list[index].file_type, file_type_key, MAX_FILE_TYPE - 1);
            magic_list[index].file_type[MAX_FILE_TYPE - 1] = '\0';

            const char *hex_string = json_string_value(magic_value);
            size_t len = strlen(hex_string) / 2;
            for (size_t i = 0; i < len; i++)
            {
                sscanf(hex_string + 2 * i, "%2hhx", &magic_list[index].magic_bytes[i]);
            }
            magic_list[index].magic_length = len;
            magic_list[index].offset = 0;
            index++;
        }
    }

    *count = index;
    json_decref(root);
    return magic_list;
}

int str_casecmp(const char *s1, const char *s2)
{
    while (*s1 && *s2)
    {
        if (tolower((unsigned char)*s1) != tolower((unsigned char)*s2))
        {
            return tolower((unsigned char)*s1) - tolower((unsigned char)*s2);
        }
        s1++;
        s2++;
    }
    return *s1 - *s2;
}

int verify_file_integrity(const char *filename, const MagicBytes *magic_list, size_t count, const char *file_type)
{
    FILE *file = fopen(filename, "rb");
    if (!file)
    {
        perror("Error opening file");
        return 0;
    }

    uint8_t buffer[MAX_MAGIC_BYTES];
    size_t read_bytes = fread(buffer, 1, MAX_MAGIC_BYTES, file);
    if (read_bytes < MAX_MAGIC_BYTES)
    {
        if (feof(file))
        {
            fprintf(stderr, "Unexpected end of file while reading.\n");
        }
        else if (ferror(file))
        {
            perror("Error reading file");
        }
        fclose(file);
        return 0;
    }
    fclose(file);

    for (size_t i = 0; i < count; i++)
    {
        if (str_casecmp(file_type, magic_list[i].file_type) == 0)
        {
            if (memcmp(buffer + magic_list[i].offset, magic_list[i].magic_bytes, magic_list[i].magic_length) == 0)
            {
                printf("File matches type %s\n", file_type);
                return 1;
            }
            else
            {
                printf("Mismatch for type %s\n", file_type);
                return 0;
            }
        }
    }

    fprintf(stderr, "File type %s not found in magic bytes list\n", file_type);
    return 0;
}

void auto_detect(const char *filename, const MagicBytes *magic_list, size_t count)
{
    FILE *file = fopen(filename, "rb");
    if (!file)
    {
        perror("Error opening file");
        return;
    }

    uint8_t buffer[MAX_MAGIC_BYTES];
    size_t read_bytes = fread(buffer, 1, MAX_MAGIC_BYTES, file);
    if (read_bytes < MAX_MAGIC_BYTES)
    {
        if (feof(file))
        {
            fprintf(stderr, "Unexpected end of file while reading.\n");
        }
        else if (ferror(file))
        {
            perror("Error reading file");
        }
        fclose(file);
        return;
    }
    fclose(file);

    for (size_t i = 0; i < count; i++)
    {
        if (memcmp(buffer + magic_list[i].offset, magic_list[i].magic_bytes, magic_list[i].magic_length) == 0)
        {
            printf("Detected file type: %s\n", magic_list[i].file_type);
            return;
        }
    }

    printf("Could not detect file type\n");
}

void brute_force(const char *filename, const MagicBytes *magic_list, size_t count)
{
    FILE *file = fopen(filename, "rb");
    if (!file)
    {
        perror("Error opening file");
        return;
    }

    uint8_t buffer[MAX_MAGIC_BYTES];
    size_t read_bytes = fread(buffer, 1, MAX_MAGIC_BYTES, file);
    if (read_bytes < MAX_MAGIC_BYTES)
    {
        if (feof(file))
        {
            fprintf(stderr, "Unexpected end of file while reading.\n");
        }
        else if (ferror(file))
        {
            perror("Error reading file");
        }
        fclose(file);
        return;
    }
    fclose(file);

    printf("Potential matches:\n");
    for (size_t i = 0; i < count; i++)
    {
        if (memcmp(buffer + magic_list[i].offset, magic_list[i].magic_bytes, magic_list[i].magic_length) == 0)
        {
            printf("- %s\n", magic_list[i].file_type);
        }
    }
}

void process_directory(const char *dir_path, const MagicBytes *magic_list, size_t count)
{
    DIR *dir = opendir(dir_path);
    if (!dir)
    {
        perror("Error opening directory");
        return;
    }

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL)
    {
        if (entry->d_name[0] == '.')
        {
            continue; // Skip hidden files and "."/".."
        }

        char filepath[1024];
        snprintf(filepath, sizeof(filepath), "%s/%s", dir_path, entry->d_name);

        struct stat file_stat;
        if (stat(filepath, &file_stat) == 0 && S_ISREG(file_stat.st_mode))
        {
            auto_detect(filepath, magic_list, count);
        }
    }

    closedir(dir);
}

void display_help()
{
    printf("Usage: file_verifier -m <magic_bytes_json> [-f <file> [-t <file_type>]] [-d <directory>] [--verbose]\n");
    printf("\nOptions:\n");
    printf("  -m <magic_bytes_json> : Path to JSON file containing magic bytes definitions.\n");
    printf("  -f <file>             : Path to a file to verify or detect type.\n");
    printf("  -t <file_type>        : File type to verify (used with -f).\n");
    printf("  -d <directory>        : Path to a directory to process.\n");
    printf("  --verbose             : Enable verbose logging for detailed output.\n");
}

int main(int argc, char *argv[])
{
    const char *magic_bytes_json = "magic_bytes.json";
    const char *file_or_dir = NULL;
    const char *file_type = NULL;

    int verbose = 0;

    static struct option long_options[] = {
        {"verbose", no_argument, 0, 'v'},
        {0, 0, 0, 0}};

    int opt;
    while ((opt = getopt_long(argc, argv, "m:f:d:t:v", long_options, NULL)) != -1)
    {
        switch (opt)
        {
        case 'm':
            magic_bytes_json = optarg;
            break;
        case 'f':
            file_or_dir = optarg;
            break;
        case 'd':
            file_or_dir = optarg;
            break;
        case 't':
            file_type = optarg;
            break;
        case 'v':
            verbose = 1;
            break;
        default:
            display_help();
            return EXIT_FAILURE;
        }
    }

    if (!magic_bytes_json || !file_or_dir)
    {
        display_help();
        return EXIT_FAILURE;
    }

    size_t count;
    MagicBytes *magic_list = load_magic_bytes(magic_bytes_json, &count);

    if (file_or_dir && file_type)
    {
        if (verbose)
        {
            printf("Verifying file: %s against type: %s\n", file_or_dir, file_type);
        }
        if (!verify_file_integrity(file_or_dir, magic_list, count, file_type))
        {
            printf("Verification failed. Attempting brute force...\n");
            brute_force(file_or_dir, magic_list, count);
        }
    }
    else
    {
        struct stat path_stat;
        if (stat(file_or_dir, &path_stat) == -1)
        {
            perror("Error accessing file or directory");
            free(magic_list);
            return EXIT_FAILURE;
        }

        if (S_ISDIR(path_stat.st_mode))
        {
            DIR *dir = opendir(file_or_dir);
            if (!dir)
            {
                perror("Error opening directory");
                free(magic_list);
                return EXIT_FAILURE;
            }

            struct dirent *entry;
            while ((entry = readdir(dir)) != NULL)
            {
                if (entry->d_name[0] == '.')
                {
                    if (verbose)
                    {
                        printf("Skipping hidden file: %s\n", entry->d_name);
                    }
                    continue;
                }

                char filepath[1024];
                snprintf(filepath, sizeof(filepath), "%s/%s", file_or_dir, entry->d_name);

                struct stat entry_stat;
                if (stat(filepath, &entry_stat) == 0 && S_ISREG(entry_stat.st_mode))
                {
                    if (verbose)
                    {
                        printf("Processing file: %s\n", filepath);
                    }
                    auto_detect(filepath, magic_list, count);
                }
            }

            closedir(dir);
        }
        else if (S_ISREG(path_stat.st_mode))
        {
            if (verbose)
            {
                printf("Processing file: %s\n", file_or_dir);
            }
            auto_detect(file_or_dir, magic_list, count);
        }
        else
        {
            fprintf(stderr, "Error: %s is not a valid file or directory\n", file_or_dir);
        }
    }

    free(magic_list);
    return EXIT_SUCCESS;
}