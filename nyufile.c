//References: https://man7.org/linux/man-pages/man3/getopt.3.html, https://man7.org/linux/man-pages/man2/mmap.2.html, https://man7.org/linux/man-pages/man2/open.2.html, https://linux.die.net/man/2/fstat, https://www.tutorialspoint.com/c_standard_library/c_function_memcpy.htm, https://stackoverflow.com/questions/29252261/how-to-merge-two-hex-numbers-to-one-number-and-then-convert-it-into-decimal, https://www.tutorialspoint.com/c_standard_library/c_function_memcpy.htm, https://stackoverflow.com/questions/3784263/converting-an-int-into-a-4-byte-char-array-c, https://linux.die.net/man/3/sha1, https://www.quora.com/How-can-I-convert-decimals-to-octals-and-hexadecimals-in-C-programming, https://www.tutorialspoint.com/c_standard_library/c_function_sprintf.htm
//I asked chatGPT about how to keep track of the command line arguments and execute the corresponding function and it helped me came up with the idea of keeping flag variables. 
//I asked chatGPT about how to convert the computed SHA-1 with the SHA1() function into hexadecimal, and it hinted me to use sprintf(). 
//I asked chatGPT about how to convert the hex dump corresponding to the next cluster into a little-endian representation and it hinted me to use bitwise operators(>> and &). 
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <string.h>
#include <ctype.h>
#include <openssl/sha.h>
#define SHA_DIGEST_LENGTH 20
#pragma pack(push,1)
typedef struct BootEntry {
  unsigned char  BS_jmpBoot[3];     // Assembly instruction to jump to boot code
  unsigned char  BS_OEMName[8];     // OEM Name in ASCII
  unsigned short BPB_BytsPerSec;    // Bytes per sector. Allowed values include 512, 1024, 2048, and 4096
  unsigned char  BPB_SecPerClus;    // Sectors per cluster (data unit). Allowed values are powers of 2, but the cluster size must be 32KB or smaller
  unsigned short BPB_RsvdSecCnt;    // Size in sectors of the reserved area
  unsigned char  BPB_NumFATs;       // Number of FATs
  unsigned short BPB_RootEntCnt;    // Maximum number of files in the root directory for FAT12 and FAT16. This is 0 for FAT32
  unsigned short BPB_TotSec16;      // 16-bit value of number of sectors in file system
  unsigned char  BPB_Media;         // Media type
  unsigned short BPB_FATSz16;       // 16-bit size in sectors of each FAT for FAT12 and FAT16. For FAT32, this field is 0
  unsigned short BPB_SecPerTrk;     // Sectors per track of storage device
  unsigned short BPB_NumHeads;      // Number of heads in storage device
  unsigned int   BPB_HiddSec;       // Number of sectors before the start of partition
  unsigned int   BPB_TotSec32;      // 32-bit value of number of sectors in file system. Either this value or the 16-bit value above must be 0
  unsigned int   BPB_FATSz32;       // 32-bit size in sectors of one FAT
  unsigned short BPB_ExtFlags;      // A flag for FAT
  unsigned short BPB_FSVer;         // The major and minor version number
  unsigned int   BPB_RootClus;      // Cluster where the root directory can be found
  unsigned short BPB_FSInfo;        // Sector where FSINFO structure can be found
  unsigned short BPB_BkBootSec;     // Sector where backup copy of boot sector is located
  unsigned char  BPB_Reserved[12];  // Reserved
  unsigned char  BS_DrvNum;         // BIOS INT13h drive number
  unsigned char  BS_Reserved1;      // Not used
  unsigned char  BS_BootSig;        // Extended boot signature to identify if the next three values are valid
  unsigned int   BS_VolID;          // Volume serial number
  unsigned char  BS_VolLab[11];     // Volume label in ASCII. User defines when creating the file system
  unsigned char  BS_FilSysType[8];  // File system type label in ASCII
} BootEntry;
#pragma pack(pop)
#pragma pack(push,1)
typedef struct DirEntry {
  unsigned char  DIR_Name[11];      // File name
  unsigned char  DIR_Attr;          // File attributes
  unsigned char  DIR_NTRes;         // Reserved
  unsigned char  DIR_CrtTimeTenth;  // Created time (tenths of second)
  unsigned short DIR_CrtTime;       // Created time (hours, minutes, seconds)
  unsigned short DIR_CrtDate;       // Created day
  unsigned short DIR_LstAccDate;    // Accessed day
  unsigned short DIR_FstClusHI;     // High 2 bytes of the first cluster address
  unsigned short DIR_WrtTime;       // Written time (hours, minutes, seconds
  unsigned short DIR_WrtDate;       // Written day
  unsigned short DIR_FstClusLO;     // Low 2 bytes of the first cluster address
  unsigned int   DIR_FileSize;      // File size in bytes. (0 for directories)
} DirEntry;
#pragma pack(pop)
char* removeTrailingZeroes(unsigned char* name);


int main(int argc, char *argv[]){
    (void)argc;
    int opt;
    int i_flag = 0;
    int l_flag = 0;
    int r_flag = 0;
    int R_flag = 0; 
    int s_flag = 0;
    char* filename = NULL;
    char* sha1 = NULL;
    while((opt = getopt(argc, argv, ":ilr:R:s:")) != -1){
        switch(opt) {
            case 'i':
                i_flag = 1;
                break;
            case 'l':
                l_flag = 1;
                break;
            case 'r':
                r_flag = 1;
                filename = optarg;
                break;
            case 'R':
                R_flag = 1;
                filename = optarg;
                break;
            case 's':
                s_flag = 1;
                sha1 = optarg;
                break;
            case '?':   
                printf("Usage: ./nyufile disk <options>\n  %-23sPrint the file system information.\n  %-23sList the root directory.\n  %-23sRecover a contiguous file.\n  %-23sRecover a possibly non-contiguous file.\n", "-i", "-l", "-r filename [-s sha1]", "-R filename -s sha1");
                exit(1); 
            case ':':
                printf("Usage: ./nyufile disk <options>\n  %-23sPrint the file system information.\n  %-23sList the root directory.\n  %-23sRecover a contiguous file.\n  %-23sRecover a possibly non-contiguous file.\n", "-i", "-l", "-r filename [-s sha1]", "-R filename -s sha1");
                exit(1); 
        }
    }
    if(argc <= 2 || ((i_flag == 1 || l_flag == 1) && argv[optind+1] != NULL) || (R_flag == 1 && s_flag == 0)){
        printf("Usage: ./nyufile disk <options>\n  %-23sPrint the file system information.\n  %-23sList the root directory.\n  %-23sRecover a contiguous file.\n  %-23sRecover a possibly non-contiguous file.\n", "-i", "-l", "-r filename [-s sha1]", "-R filename -s sha1");
        exit(1);
    }
    int fd = open(argv[optind], O_RDWR);
    if (fd == -1){
        fprintf(stderr, "No such file");
        exit(0);
    }
    struct stat sb;
    if (fstat(fd, &sb) == -1){
        fprintf(stderr, "Error getting size");
        exit(0);
    }
    char *addr = mmap(NULL, sb.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    BootEntry *boot_sector = (BootEntry*) addr;
    int FAT_num = boot_sector->BPB_NumFATs;
    int byte_per_sector = boot_sector->BPB_BytsPerSec;
    int sector_per_cluster = boot_sector->BPB_SecPerClus;
    int reserved_sector = boot_sector->BPB_RsvdSecCnt;
    int sector_in_FAT = boot_sector->BPB_FATSz32;
    int root_cl = boot_sector->BPB_RootClus;
    char *root = addr + reserved_sector * byte_per_sector + FAT_num * sector_in_FAT * byte_per_sector + (root_cl - 2) *  byte_per_sector * sector_per_cluster;
    char *fat = addr + reserved_sector * byte_per_sector + root_cl * 4;

    if (i_flag) {
        printf("Number of FATs = %d\nNumber of bytes per sector = %d\nNumber of sectors per cluster = %d\nNumber of reserved sectors = %d\n", FAT_num, byte_per_sector, sector_per_cluster, reserved_sector);
    } else if (l_flag) {
        int entriesCount = 0; 
        while(1){
            for(int i = 0; i < byte_per_sector * sector_per_cluster; i+=32){
                DirEntry *dir = (DirEntry*) (root + i);
                unsigned char name[8];
                unsigned char ext[4];
                for(int j = 0; j < 11; j++){
                    if(j < 8){
                        name[j] = dir->DIR_Name[j];
                    }
                    else{
                        ext[j - 8] = dir->DIR_Name[j];
                    }
                }
                name[8] ='\0';
                ext[3] = '\0';
                if(dir->DIR_Name[0] == 0x00){
                    break;
                }  
                else if(dir->DIR_Name[0] == 0xE5 || dir->DIR_Attr == 0x0F){
                    continue;
                }
                else if(dir->DIR_Attr == 0x10){
                    if(ext[0] == 0x00 || ext[0] == 0x20){
                        printf("%s/ (starting cluster = %d)\n", removeTrailingZeroes(name), dir->DIR_FstClusLO + dir->DIR_FstClusHI);
                    }
                    else{
                        printf("%s.%s/ (starting cluster = %d)\n", removeTrailingZeroes(name),removeTrailingZeroes(ext), dir->DIR_FstClusLO + dir->DIR_FstClusHI);
                    }
                    entriesCount++;
                    continue;
                }
                else if(dir->DIR_FileSize == 0){
                    if(ext[0] == 0x00 || ext[0] == 0x20){
                        printf("%s (size = 0)\n", removeTrailingZeroes(name));
                    }
                    else{
                        printf("%s.%s (size = 0)\n", removeTrailingZeroes(name),removeTrailingZeroes(ext));
                    }
                    entriesCount++;
                    continue;
                }
                else{
                    if(ext[0] == 0x00 || ext[0] == 0x20){
                        printf("%s (size = %d, starting cluster = %d)\n", removeTrailingZeroes(dir->DIR_Name), dir->DIR_FileSize, dir->DIR_FstClusLO + dir->DIR_FstClusHI);
                    }
                    else{
                        printf("%s.%s (size = %d, starting cluster = %d)\n", removeTrailingZeroes(name),removeTrailingZeroes(ext), dir->DIR_FileSize, dir->DIR_FstClusLO + dir->DIR_FstClusHI);
                    }
                    entriesCount++;
                }    
            }
            unsigned int nextCl; 
            memcpy(&nextCl, fat, 4);
            if(nextCl >= 0x0ffffff8){
                break;
            }
            root = addr + reserved_sector * byte_per_sector + FAT_num * sector_in_FAT * byte_per_sector + (nextCl - 2) * byte_per_sector * sector_per_cluster;
            fat = addr + reserved_sector * byte_per_sector + nextCl * 4;
        }
        munmap(addr, sb.st_size);
        printf("Total number of entries = %d\n", entriesCount);
    } else if (r_flag) {
            if (sha1 == NULL) {
                DirEntry *removed_dir;
                int count = 0;
                char* check_file = filename + 1;
                while(1){
                    for(int i = 0; i < byte_per_sector * sector_per_cluster; i+=32){
                        DirEntry *dir = (DirEntry*) (root + i);
                        unsigned char name[8];
                        unsigned char ext[4];
                        for(int j = 1; j < 11; j++){
                            if(j < 8){
                                name[j - 1] = dir->DIR_Name[j];
                            }
                            else{
                                ext[j - 8] = dir->DIR_Name[j];
                            }
                        }
                        name[7] = '\0';
                        ext[3] = '\0';
                        char fullname[11] = "";
                        if(ext[0] == 0x00 || ext[0] == 0x20){
                            sprintf(fullname, "%s", removeTrailingZeroes(name));
                        }
                        else{
                            sprintf(fullname, "%s.%s", removeTrailingZeroes(name), removeTrailingZeroes(ext));
                        }
                        if(dir->DIR_Name[0] == 0x00){
                            break;
                        }  
                        else if((dir->DIR_Name[0] == 0xE5) && (strcmp(fullname, check_file) == 0)){
                            removed_dir = dir;
                            count++;
                        }
                    }
                    unsigned int nextCl; 
                    memcpy(&nextCl, fat, 4);
                    if(nextCl >= 0x0ffffff8){
                        break;
                    }
                    root = addr + reserved_sector * byte_per_sector + FAT_num * sector_in_FAT * byte_per_sector + (nextCl - 2) * byte_per_sector * sector_per_cluster;
                    fat = addr + reserved_sector * byte_per_sector + nextCl * 4;
                }
                if(count == 0){
                    printf("%s: file not found\n", filename);
                }
                else if(count > 1){
                    printf("%s: multiple candidates found\n", filename);
                }
                else{
                    if(removed_dir->DIR_FileSize == 0){
                        removed_dir->DIR_Name[0] = filename[0];
                    }
                    else{
                        removed_dir->DIR_Name[0] = filename[0];
                        int cluster = removed_dir->DIR_FstClusLO + removed_dir->DIR_FstClusHI;
                        int num_cluster = ((removed_dir->DIR_FileSize) % (byte_per_sector * sector_per_cluster) != 0) ?  ((removed_dir->DIR_FileSize) / (byte_per_sector * sector_per_cluster) + 1) : ((removed_dir->DIR_FileSize) / (byte_per_sector * sector_per_cluster));
                        for(int i = 0; i < num_cluster; i++){
                            char* fat1_rec = addr + reserved_sector * byte_per_sector + (cluster + i) * 4;
                            char* fat2_rec = addr + reserved_sector * byte_per_sector + sector_in_FAT * byte_per_sector + (cluster + i) * 4;
                            if(num_cluster - i == 1){
                                unsigned char data[4] = {0xf8, 0xff, 0xff, 0x0f};
                                memcpy(fat1_rec, data, 4);
                                memcpy(fat2_rec, data, 4);
                            }
                            else{
                                unsigned char data[4];
                                data[0] = ((cluster + i + 1)) & 0xFF;
                                data[1] = ((cluster + i + 1) >> 8) & 0xFF;
                                data[2] = ((cluster + i + 1) >> 16)& 0xFF;
                                data[3] = ((cluster + i + 1) >> 24) & 0xFF;        
                                memcpy(fat1_rec, data, 4);
                                memcpy(fat2_rec, data, 4);
                            }
                        }
                    }
                    printf("%s: successfully recovered\n", filename);
                }
                munmap(addr, sb.st_size);
            } else {
                DirEntry *removed_dir;
                int count = 0;
                char* check_file = filename + 1;
                while(1){
                    for(int i = 0; i < byte_per_sector * sector_per_cluster; i+=32){
                        DirEntry *dir = (DirEntry*) (root + i);
                        unsigned char md[SHA_DIGEST_LENGTH];
                        int first_cluster= dir->DIR_FstClusLO + dir->DIR_FstClusHI;
                        char *curr_cluster = addr + reserved_sector * byte_per_sector + FAT_num * sector_in_FAT * byte_per_sector + (first_cluster - 2) *  byte_per_sector * sector_per_cluster;
                        SHA1((unsigned char*)curr_cluster, dir->DIR_FileSize, md);
                        char hex_md[sizeof(md) * 2]; 
                        for (int k = 0; k < (int)sizeof(md); k++) {
                            sprintf(hex_md + k * 2, "%02x", md[k]); 
                        }
                        unsigned char name[8];
                        unsigned char ext[4];
                        for(int j = 1; j < 11; j++){
                            if(j < 8){
                                name[j - 1] = dir->DIR_Name[j];
                            }
                            else{
                                ext[j - 8] = dir->DIR_Name[j];
                            }
                        }
                        name[7] = '\0';
                        ext[3] = '\0';
                        char fullname[11] = "";
                        if(ext[0] == 0x00 || ext[0] == 0x20){
                            sprintf(fullname, "%s", removeTrailingZeroes(name));
                        }
                        else{
                            sprintf(fullname, "%s.%s", removeTrailingZeroes(name), removeTrailingZeroes(ext));
                        }
                        if(dir->DIR_Name[0] == 0x00){
                            break;
                        }  
                        else if((dir->DIR_Name[0] == 0xE5) && (strcmp(fullname, check_file) == 0) && (memcmp(hex_md, sha1, SHA_DIGEST_LENGTH) == 0)){
                            removed_dir = dir;
                            count++;
                        }
                    }
                    unsigned int nextCl; 
                    memcpy(&nextCl, fat, 4);
                    if(nextCl >= 0x0ffffff8){
                        break;
                    }
                    root = addr + reserved_sector * byte_per_sector + FAT_num * sector_in_FAT * byte_per_sector + (nextCl - 2) * byte_per_sector * sector_per_cluster;
                    fat = addr + reserved_sector * byte_per_sector + nextCl * 4;
                }
                if(count == 0){
                    printf("%s: file not found\n", filename);
                } 
                else{
                    if(removed_dir->DIR_FileSize == 0){
                        removed_dir->DIR_Name[0] = filename[0];
                    }
                    else{
                        removed_dir->DIR_Name[0] = filename[0];
                        int cluster = removed_dir->DIR_FstClusLO + removed_dir->DIR_FstClusHI;
                        int num_cluster = ((removed_dir->DIR_FileSize) % (byte_per_sector * sector_per_cluster) != 0) ?  ((removed_dir->DIR_FileSize) / (byte_per_sector * sector_per_cluster) + 1) : ((removed_dir->DIR_FileSize) / (byte_per_sector * sector_per_cluster));
                        for(int i = 0; i < num_cluster; i++){
                            char* fat1_rec = addr + reserved_sector * byte_per_sector + (cluster + i) * 4;
                            char* fat2_rec = addr + reserved_sector * byte_per_sector + sector_in_FAT * byte_per_sector + (cluster + i) * 4;
                            if(num_cluster - i == 1){
                                unsigned char data[4] = {0xf8, 0xff, 0xff, 0x0f};
                                memcpy(fat1_rec, data, 4);
                                memcpy(fat2_rec, data, 4);
                            }
                            else{
                                unsigned char data[4];
                                data[0] = ((cluster + i + 1)) & 0xFF;
                                data[1] = ((cluster + i + 1) >> 8) & 0xFF;
                                data[2] = ((cluster + i + 1) >> 16)& 0xFF;
                                data[3] = ((cluster + i + 1) >> 24) & 0xFF;        
                                memcpy(fat1_rec, data, 4);
                                memcpy(fat2_rec, data, 4);
                            }
                        }
                    }
                    printf("%s: successfully recovered with SHA-1\n", filename);
                }
                munmap(addr, sb.st_size);
            }
    } else if (R_flag) {
    }
}

char* removeTrailingZeroes(unsigned char* name){
    int i = 0;
    while(name[i] != 0x20 && name[i] != 0x00){
        i++;
    }
    name[i] = '\0';
    return (char*)name;
}
