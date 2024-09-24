#include <stdio.h>
#include <errno.h>
#include <stdint.h>
#include <elf.h>
#include <string.h>
#include <sys/mman.h>
#include <errno.h>

#include "student_loader.h"

#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS 0x20 /* Don't use a file.  */
#endif

// Entry point of loaded binary in as a func ptr
// Hint, you want this after you've finished loading :)
void (*foo)(void);

/**
 * @brief Given a ELF header, pretty print some data from the ELF header
 * @param e64_hdr pointer to ELF header
 */
static void print_elf64_header(Elf64_Ehdr *e64_hdr)
{

    /* Storage capacity class */
    printf("Storage class\t= ");
    switch (e64_hdr->e_ident[EI_CLASS])
    {
    case ELFCLASS32:
        printf("32-bit objects\n");
        break;

    case ELFCLASS64:
        printf("64-bit objects\n");
        break;

    default:
        printf("INVALID CLASS\n");
        break;
    }

    /* Data Format */
    printf("Data format\t= ");
    switch (e64_hdr->e_ident[EI_DATA])
    {
    case ELFDATA2LSB:
        printf("2's complement, little endian\n");
        break;

    case ELFDATA2MSB:
        printf("2's complement, big endian\n");
        break;

    default:
        printf("INVALID Format\n");
        break;
    }

    /* OS ABI */
    printf("OS ABI\t\t= ");
    switch (e64_hdr->e_ident[EI_OSABI])
    {
    case ELFOSABI_SYSV:
        printf("UNIX System V ABI\n");
        break;

    case ELFOSABI_HPUX:
        printf("HP-UX\n");
        break;

    case ELFOSABI_NETBSD:
        printf("NetBSD\n");
        break;

    case ELFOSABI_LINUX:
        printf("Linux\n");
        break;

    case ELFOSABI_SOLARIS:
        printf("Sun Solaris\n");
        break;

    case ELFOSABI_AIX:
        printf("IBM AIX\n");
        break;

    case ELFOSABI_IRIX:
        printf("SGI Irix\n");
        break;

    case ELFOSABI_FREEBSD:
        printf("FreeBSD\n");
        break;

    case ELFOSABI_TRU64:
        printf("Compaq TRU64 UNIX\n");
        break;

    case ELFOSABI_MODESTO:
        printf("Novell Modesto\n");
        break;

    case ELFOSABI_OPENBSD:
        printf("OpenBSD\n");
        break;

    case ELFOSABI_ARM_AEABI:
        printf("ARM EABI\n");
        break;

    case ELFOSABI_ARM:
        printf("ARM\n");
        break;

    case ELFOSABI_STANDALONE:
        printf("Standalone (embedded) app\n");
        break;

    default:
        printf("Unknown (0x%x)\n", e64_hdr->e_ident[EI_OSABI]);
        break;
    }

    /* ELF filetype */
    printf("Filetype \t= ");
    switch (e64_hdr->e_type)
    {
    case ET_NONE:
        printf("N/A (0x0)\n");
        break;

    case ET_REL:
        printf("Relocatable\n");
        break;

    case ET_EXEC:
        printf("Executable\n");
        break;

    case ET_DYN:
        printf("Shared Object\n");
        break;
    default:
        printf("Unknown (0x%x)\n", e64_hdr->e_type);
        break;
    }

    /* ELF Machine-id */
    printf("Machine\t\t= ");
    switch (e64_hdr->e_machine)
    {
    case EM_NONE:
        printf("None (0x0)\n");
        break;

    case EM_386:
        printf("INTEL x86 (0x%x)\n", EM_386);
        break;

    case EM_X86_64:
        printf("AMD x86_64 (0x%x)\n", EM_X86_64);
        break;

    case EM_AARCH64:
        printf("AARCH64 (0x%x)\n", EM_AARCH64);
        break;

    default:
        printf(" 0x%x\n", e64_hdr->e_machine);
        break;
    }

    /* Entry point */
    printf("Entry point\t= 0x%08lx\n", e64_hdr->e_entry);

    /* ELF header size in bytes */
    printf("ELF header size\t= 0x%08x\n", e64_hdr->e_ehsize);

    /* Program Header */
    printf("\nProgram Header\t= ");
    printf("0x%08lx\n", e64_hdr->e_phoff);            /* start */
    printf("\t\t  %d entries\n", e64_hdr->e_phnum);   /* num entry */
    printf("\t\t  %d bytes\n", e64_hdr->e_phentsize); /* size/entry */

    /* Section header starts at */
    printf("\nSection Header\t= ");
    printf("0x%08lx\n", e64_hdr->e_shoff);            /* start */
    printf("\t\t  %d entries\n", e64_hdr->e_shnum);   /* num entry */
    printf("\t\t  %d bytes\n", e64_hdr->e_shentsize); /* size/entry */
    printf("\t\t  0x%08x (string table offset)\n", e64_hdr->e_shstrndx);

    /* File flags (Machine specific)*/
    printf("\nFile flags \t= 0x%08x\n", e64_hdr->e_flags);

    /* ELF file flags are machine specific.
     * INTEL implements NO flags.
     * ARM implements a few.
     * Add support below to parse ELF file flags on ARM
     */
    int32_t ef = e64_hdr->e_flags;
    printf("\t\t  ");

    if (ef & EF_ARM_RELEXEC)
        printf(",RELEXEC ");

    if (ef & EF_ARM_HASENTRY)
        printf(",HASENTRY ");

    if (ef & EF_ARM_INTERWORK)
        printf(",INTERWORK ");

    if (ef & EF_ARM_APCS_26)
        printf(",APCS_26 ");

    if (ef & EF_ARM_APCS_FLOAT)
        printf(",APCS_FLOAT ");

    if (ef & EF_ARM_PIC)
        printf(",PIC ");

    if (ef & EF_ARM_ALIGN8)
        printf(",ALIGN8 ");

    if (ef & EF_ARM_NEW_ABI)
        printf(",NEW_ABI ");

    if (ef & EF_ARM_OLD_ABI)
        printf(",OLD_ABI ");

    if (ef & EF_ARM_SOFT_FLOAT)
        printf(",SOFT_FLOAT ");

    if (ef & EF_ARM_VFP_FLOAT)
        printf(",VFP_FLOAT ");

    if (ef & EF_ARM_MAVERICK_FLOAT)
        printf(",MAVERICK_FLOAT ");

    printf("\n");

    /* MSB of flags conatins ARM EABI version */
    printf("ARM EABI\t= Version %d\n", (ef & EF_ARM_EABIMASK) >> 24);

    printf("\n"); /* End of ELF header */
}

/**
 * @brief Given a ELF header, check if the elf is a 64-bit ELF
 * @param hdr pointer to ELF header
 * @note Here we use Elf64_Ehdr as the type, because the data we are checking isn't type specific
 * and thus can use either 32 or 64 bit ELF structs. See man elf.
 */
static int is_elf64(Elf64_Ehdr *hdr)
{
    int result = 0;
    // Check its an ELF
    if (!strncmp((char *)hdr->e_ident, "\177ELF", 4))
    {
        printf("[+] ELF Magic Match\n");
        // Check its also 64-bit
        if (ELFCLASS64 == hdr->e_ident[EI_CLASS])
        {
            printf("[+] ELF is 64-bit\n");
            result = 1;
        }
        else
        {
            printf("[-] 32-bit ELF's not supported");
        }
    }
    else
    {
        printf("[-] ELFMAGIC mismatch!\n");
    }

    return result;
}

/**
 * @brief Given the raw binary data and the elf header, pretty print the Section Header table
 * @param e64_hdr pointer to ELF 64-bit header
 * @param fdata byte pointer to raw binary data (the raw data of the file you are trying to load)
 */
static void print_elf64_secheaders(Elf64_Ehdr *e64_hdr, uint8_t *fdata)
{
    // Set helper pointer to the Section Header table offset
    Elf64_Shdr *shdr_table = (Elf64_Shdr *)(fdata + e64_hdr->e_shoff);
    // Section Header String Table
    char *shdr_str_table = NULL;

    // This index tells us which Section Header contains
    // the Section Header String Table (also a section).
    // This table contains the names of each of the section
    // headers present in the binary
    shdr_str_table = (char *)fdata + shdr_table[e64_hdr->e_shstrndx].sh_offset;

    printf("Section Headers:\n");
    printf("========================================");
    printf("========================================\n");
    printf(" idx offset     load-addr  size       algn"
           " flags      type       section\n");
    printf("========================================");
    printf("========================================\n");

    for (int i = 0; i < e64_hdr->e_shnum; i++)
    {
        printf("%3d  ", i);
        printf("0x%08lx ", shdr_table[i].sh_offset);
        printf("0x%08lx ", shdr_table[i].sh_addr);
        printf("0x%08lx ", shdr_table[i].sh_size);
        printf("%4ld ", shdr_table[i].sh_addralign);
        printf("0x%08lx ", shdr_table[i].sh_flags);
        printf("0x%08x ", shdr_table[i].sh_type);
        printf("%s\t", (shdr_str_table + shdr_table[i].sh_name));
        printf("\n");
    }
    printf("========================================");
    printf("========================================\n");
    printf("\n"); /* end of section header table */
}

/**
 * @brief Given the Program Header flag from a program header, pretty print the
 *        Program Header permissions
 * @param flag program header flag
 */
static void print_elf64_progheader_flags(Elf64_Word flag)
{
    char flgstr[3] = {'.', '.', '.'};
    if (flag & PF_R)
    {
        flgstr[0] = 'R';
    }
    if (flag & PF_W)
    {
        flgstr[1] = 'W';
    }
    if (flag & PF_X)
    {
        flgstr[2] = 'X';
    }
    printf("%s ", flgstr);
}

/**
 * @brief Given the raw binary data and the elf header, pretty print the Program Header table
 * @param e64_hdr pointer to ELF 64-bit header
 * @param fdata byte pointer to raw binary data (the raw data of the file you are trying to load)
 */
static void print_elf64_progheaders(Elf64_Ehdr *e64_hdr, uint8_t *fdata)
{
    // Set helper pointer to the Program Header table offset
    Elf64_Phdr *phdr_table = (Elf64_Phdr *)(fdata + e64_hdr->e_phoff);

    printf("Program Headers:\n");
    printf("========================================");
    printf("========================================\n");
    printf(" Type Offset     VirtAddr   PhysAddr   FileSz"
           "     MemSz      Flg Align\n");
    printf("========================================");
    printf("========================================\n");
    for (int i = 0; i < e64_hdr->e_phnum; i++)
    {
        printf("  %u   ", phdr_table[i].p_type);
        printf("0x%08lx ", phdr_table[i].p_offset);
        printf("0x%08lx ", phdr_table[i].p_vaddr);
        printf("0x%08lx ", phdr_table[i].p_paddr);
        printf("0x%08lx ", phdr_table[i].p_filesz);
        printf("0x%08lx ", phdr_table[i].p_memsz);
        print_elf64_progheader_flags(phdr_table[i].p_flags);
        printf("0x%08lx\t", phdr_table[i].p_align);
        printf("\n");
    }
}

uint64_t student_load(uint8_t *fdata, size_t size)
{

    // Students fill out

    // Step 1: you have raw data. Cast that to a Elf64_ehdr,
    // then you can use the provided is_elf64() and print_elf64_header() call to print

    // Step 2: You've confirmed its ELF you support
    // From here you have options on how you can move forward
    // You can extract the program_headers needed for easy access then load
    // or you can load straight from the raw data
    // for these simple bins you won't need to worry about section headers

    return 0;
}

void student_jump(uint64_t entry)
{
    // Student fill out
    foo = (void (*)())entry;
}