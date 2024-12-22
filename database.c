#include <string.h>
#include <stdbool.h>
#include "base.h"

void CreateDatabase(PATH databasename) {
    makedir(databasename);
    gen_keys(databasename);
    KEY pub = load_pubkey(databasename);
    ensure_shared_key(pub, databasename);
}

void CreateTable(PATH databasename, PATH tablename, const char* data) {
    PATH fullpath = catpath(databasename, tablename);
    if (!fullpath) {
        perror("Path creation failed");
        exit(EXIT_FAILURE);
    }

    if (CheckDataSet(fullpath) == false) {
        SetHeader header;
        snprintf(header.tablename, sizeof(header.tablename), "%s", tablename);
        header.datasize = str_len(data);
        
        FILE* file = open_file(databasename, tablename, "wb");
        if (!file) {
            free(fullpath);
            exit(EXIT_FAILURE);
        }
        
        fwrite(&header, HEADERSIZE, 1, file);
        fwrite(data, 1, header.datasize, file);
        close_file(databasename, tablename, file);
    }
    free(fullpath);
}

void AddMetaData(PATH databasename, PATH tablename, const char* metadata) {
    PATH fullpath = catpath(databasename, tablename);
    if (!fullpath) {
        perror("Path creation failed");
        exit(EXIT_FAILURE);
    }

    if (CheckDataSet(fullpath) == true) {
        SetHeader MetaHeader;
        snprintf(MetaHeader.tablename, sizeof(MetaHeader.tablename), "meta_%s", tablename);
        MetaHeader.datasize = str_len(metadata);

        FILE* file = open_file(databasename, tablename, "ab");
        if (!file) {
            free(fullpath);
            exit(EXIT_FAILURE);
        }
        
        fwrite(&MetaHeader, HEADERSIZE, 1, file);
        fwrite(metadata, 1, MetaHeader.datasize, file);
        close_file(databasename, tablename, file);
    }
    free(fullpath);
}

char* ReadTable(PATH databasename, PATH tablename, bool Metadata) {
    PATH fullpath = catpath(databasename, tablename);
    if (!fullpath) {
        perror("Path creation failed");
        return NULL;
    }

    if (CheckDataSet(fullpath) == true) {
        FILE* file = open_file(databasename, tablename, "rb");
        free(fullpath);
        
        if (file == NULL) {
            perror("Error opening file");
            return NULL;
        }

        SetHeader Header;
        if (fread(&Header, HEADERSIZE, 1, file) != 1) {
            close_file(databasename, tablename, file);
            perror("Error reading header");
            return NULL;
        }

        if (Header.datasize <= 0) {
            close_file(databasename, tablename, file);
            perror("Invalid data size");
            return NULL;
        }

        char* buffer = (char*)calloc(Header.datasize + 1, sizeof(char));
        if (buffer == NULL) {
            close_file(databasename, tablename, file);
            perror("Memory allocation failed");
            return NULL;
        }

        if (fread(buffer, 1, Header.datasize, file) != Header.datasize) {
            free(buffer);
            close_file(databasename, tablename, file);
            perror("Error reading data");
            return NULL;
        }

        if (Metadata == false) {
            close_file(databasename, tablename, file);
            return buffer;
        }
        free(buffer);

        SetHeader MetaHeader;
        if (fread(&MetaHeader, HEADERSIZE, 1, file) != 1) {
            close_file(databasename, tablename, file);
            perror("Error reading metadata header");
            return NULL;
        }

        if (MetaHeader.datasize <= 0) {
            close_file(databasename, tablename, file);
            perror("Invalid metadata size");
            return NULL;
        }

        buffer = (char*)calloc(MetaHeader.datasize + 1, sizeof(char));
        if (buffer == NULL) {
            close_file(databasename, tablename, file);
            perror("Memory allocation failed");
            return NULL;
        }

        if (fread(buffer, 1, MetaHeader.datasize, file) != MetaHeader.datasize) {
            free(buffer);
            close_file(databasename, tablename, file);
            perror("Error reading metadata");
            return NULL;
        }

        close_file(databasename, tablename, file);
        return buffer;
    }
    
    free(fullpath);
    perror("Table does not exist");
    return NULL;
}

void DeleteTable(PATH databasename, PATH tablename) {
    PATH slash = catpath(databasename, "/");
    if (!slash) {
        perror("Path creation failed");
        exit(EXIT_FAILURE);
    }

    PATH path = catpath(slash, tablename);
    free(slash);
    
    if (!path) {
        perror("Path creation failed");
        exit(EXIT_FAILURE);
    }

    if (CheckDataSet(path) && remove(path) != 0) {
        free(path);
        perror("Could not delete the table");
        exit(EXIT_FAILURE);
    }
    
    free(path);
}

void UpdateTable(PATH databasename, PATH tablename, const char* data) {
    char* metadata = ReadTable(databasename, tablename, true);
    DeleteTable(databasename, tablename);
    CreateTable(databasename, tablename, data);
    if (metadata) {
        AddMetaData(databasename, tablename, metadata);
        free(metadata);
    }
}

void UpdateMetaTable(PATH databasename, PATH tablename, const char* metadata) {
    char* data = ReadTable(databasename, tablename, false);
    if (!data) {
        perror("Error reading table data");
        return;
    }
    
    DeleteTable(databasename, tablename);
    CreateTable(databasename, tablename, data);
    AddMetaData(databasename, tablename, metadata);
    free(data);
}