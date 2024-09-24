#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <elf.h>

#if defined INSTRUCTOR_EX1 || defined INSTRUCTOR_EX2 // For instructor use only
#include "instructor.h"
#elif defined STUDENT // For student use only
#include "student_loader.h"
#else // You done messed up a-a-ron
#error "One of INSTRUCTOR_EX1, INSTRUCTOR_EX2, or STUDENT, must be defined at build time. Use the one that describes you!"
#endif

#define RESULT_ONE_THEN_DONE \
    do                       \
    {                        \
        result = 1;          \
        goto done;           \
    } while (0)

int main(int argc, char **argv)
{
    struct stat stat_buf = {0};
    int fd = -1;
    int result = 0;
    uint8_t *file_data = NULL;
    ssize_t bytes_read = 0;

    // Basic setup
    if (2 != argc)
    {
        printf("usage: tiny_loader FILE\n");
        RESULT_ONE_THEN_DONE;
    }

    // Open targeted elf
    fd = open(argv[1], O_RDONLY);
    if (-1 == fd)
    {
        printf("[-] Error opening file. errno: %d\n", errno);
        RESULT_ONE_THEN_DONE;
    }
    // Pull file stats to get size
    result = fstat(fd, &stat_buf);
    if (-1 == result)
    {
        printf("[-] Error file stat. errno: %d\n", errno);
        RESULT_ONE_THEN_DONE;
    }
    // Allocate zero initialize memory to store binary
    file_data = calloc(stat_buf.st_size, sizeof(uint8_t));
    if (NULL == file_data)
    {
        printf("[-] Error allocating buffer. errno: %d\n", errno);
        RESULT_ONE_THEN_DONE;
    }
    // Loop reading until we've read all bytes
    while (bytes_read != stat_buf.st_size)
    {
        bytes_read = read(fd, (uint8_t *)file_data + bytes_read, stat_buf.st_size - bytes_read);
        if (bytes_read != stat_buf.st_size)
        {
            printf("[-] Error reading file. errno: %d\n", errno);
            RESULT_ONE_THEN_DONE;
        }
        printf("[*] Read: %zd bytes\n", bytes_read);
    }
    close(fd);
    fd = -1;
    // End setup

#if defined INSTRUCTOR_EX1 || defined INSTRUCTOR_EX2
    uint64_t addr = 0;
    addr = instructor_load(file_data, bytes_read);
    if (0 == addr)
    {
        printf("[-] Error instructor load!!\n");
        RESULT_ONE_THEN_DONE;
    }
    result = instructor_jump(addr);

#elif defined STUDENT
    // STUDENTS
    // YOUR CODE HERE

    student_load(file_data, bytes_read);

#else
#error "One of INSTRUCTOR_EX1, INSTRUCTOR_EX2, or STUDENT, must be defined at build time. Use the one that describes you!"
#endif

done:
    // Clean up time
    if (NULL != file_data)
    {
        free(file_data);
    }
    if (0 < fd)
    {
        close(fd);
        fd = -1;
    }

    return result;
}