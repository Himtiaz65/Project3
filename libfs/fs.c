#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>

#define FAT_EOC 0xFFFF

#include "fs.h"
#include "disk.h"

//declared bit fields with specific widths
struct superblock
{
	char signature[8];
	uint16_t total_blocks: 16;
	uint16_t root_dir_index: 16;
	uint16_t data_block_start_index: 16;
	uint16_t data_blocks: 16;
	uint8_t fat_blocks: 8;
	uint8_t padding[BLOCK_SIZE];
};

struct fat_entry
{
	uint16_t value;
};

struct directory_entry
{
	char filename[FS_FILENAME_LEN];
	uint32_t size;
	uint16_t first_current_blk_index;
	uint8_t padding[10];
};

//Phase 3
struct file_descriptor
{
	int used;
	int offset;
	uint16_t first_directory_index;
};

static struct superblock * sb;
static struct fat_entry *fat = NULL;	//pointer to fat
static struct directory_entry *directory = NULL;	//pointer to directory
static struct file_descriptor open_files[FS_OPEN_MAX_COUNT];	//array of FD

int fs_mount(const char *diskname)
{
	sb = (struct superblock *) malloc(sizeof(struct superblock));
	// Open the virtual disk file, then read superblock from disk, and finally verify signature
	if (block_disk_open(diskname) != 0 || block_read(0, sb) != 0 || strncmp(sb->signature, "ECS150FS", 8) != 0)
	{
		free(sb);
		return -1;
	}

	// Allocate memory for FAT
	// Calculate the size of the fat array in bytes
	size_t fat_size = sb->fat_blocks * BLOCK_SIZE;

	// Allocate memory for the fat array
	fat = (struct fat_entry *) malloc(fat_size);

	// Check if the allocation was successful
	if (fat == NULL)
	{
		return -1;
	}

	// Read the FAT from the disk
	uint8_t i;
	for (i = 0; i < sb->fat_blocks; i++)
	{
		// FAT block calculation (starting address)
		void *fat_block = &fat[i *(BLOCK_SIZE / sizeof(struct fat_entry))];

		if (block_read(i + 1, fat_block) != 0)
		{
			free(fat);
			return -1;
		}
	}

	// Allocate memory for directory
	size_t directory_size = FS_FILE_MAX_COUNT* sizeof(struct directory_entry);
	directory = (struct directory_entry *) malloc(directory_size);
	if (directory == NULL)
	{
		free(fat);
		block_disk_close();
		return -1;
	}

	// Read the root directory from the disk
	if (block_read(sb->root_dir_index, directory) != 0)
	{
		free(directory);
		free(fat);
		block_disk_close();
		return -1;
	}

	// Initialize open file descriptors
	memset(open_files, 0, sizeof(open_files));

	return 0;
}

int fs_umount(void)
{
	if (block_disk_close() != 0)
	{
		return -1;
	}

	free(directory);
	free(fat);

	//checks if any FD is in use
	for (int i = 0; i < FS_OPEN_MAX_COUNT; i++)
	{
		int isUsed = open_files[i].used;
		if (isUsed == 1)
		{
			//returns error if the above case is true
			return -1;
		}
	}

	return 0;
}

//returns no. of free blocks in FAT
uint16_t fat_free_space()
{
	uint16_t fat_free_blocks = 0;
	for (uint16_t i = 0; i < sb->data_blocks; i++)
	{
		//This check determines if the block is free or unused.
		if (fat[i].value == 0)
		{
			fat_free_blocks++;
		}
	}

	return fat_free_blocks;
}

//returns no. of free blocks in directory
uint16_t free_directory_space()
{
	uint16_t rdir_free_blocks = 0;
	for (uint16_t i = 0; i < FS_FILE_MAX_COUNT; i++)
	{
		//checks if the first character of the filename at i is a null char
		if (directory[i].filename[0] == '\0')
		{
			rdir_free_blocks++;
		}
	}

	return rdir_free_blocks;
}

int fs_info(void)
{
	if (block_disk_count() < 0)
	{
		return -1;
	}

	printf("FS Info:\n");
	printf("total_blk_count=%u\n", sb->total_blocks);
	printf("fat_blk_count=%u\n", sb->fat_blocks);
	printf("rdir_blk=%u\n", sb->root_dir_index);
	printf("data_blk=%u\n", sb->data_block_start_index);
	printf("data_blk_count=%u\n", sb->data_blocks);

	// Calculate the free ratios for FAT and root directory

	uint16_t fat_free_blocks = fat_free_space();
	uint16_t rdir_free_blocks = free_directory_space();

	printf("fat_free_ratio=%u/%u\n", fat_free_blocks, sb->data_blocks);
	printf("rdir_free_ratio=%u/%u\n", rdir_free_blocks, FS_FILE_MAX_COUNT);

	return 0;
}

////////////////////////////////////

int file_exist_or_not(const char *filename)
{
	for (int i = 0; i < FS_FILE_MAX_COUNT; i++)
	{
		if (strcmp(directory[i].filename, filename) == 0)
		{
			fprintf(stderr, "Error: The File '%s' already exists\n", filename);
			return -1;
		}
	}

	return 0;
}

int look_for_empty_start()
{
	int index_first = -1;
	for (int i = 0; i < FS_FILE_MAX_COUNT; i++)
	{
		if (directory[i].filename[0] == '\0')
		{
			index_first = i;
			break;
		}
	}

	return index_first;
}

//////////////////////////

int fs_create(const char *filename)
{
	size_t filename_length = strlen(filename);
	if (block_disk_count() < 0 || (filename == NULL || (filename_length > FS_FILENAME_LEN - 1)))
	{
		return -1;
	}

	// Check if the file already exists
	if (file_exist_or_not(filename) != 0)
	{
		return -1;
	}

	int index_first = look_for_empty_start();

	if (index_first == -1)
	{
		return -1;
	}

	// Set the directory entry for the new file
	strcpy(directory[index_first].filename, filename);
	directory[index_first].size = 0;
	directory[index_first].first_current_blk_index = FAT_EOC;

	// Write the updated root directory to the disk
	if (block_write(sb->root_dir_index, directory) != 0)
	{
		return -1;
	}

	return 0;
}

int fs_delete(const char *filename)
{
	if (block_disk_count() < 0 || filename == NULL)
	{
		return -1;
	}

	int index_first = -1;
	char *current_filename;

	int i = 0;
	while (i < FS_FILE_MAX_COUNT)
	{
		current_filename = directory[i].filename;	//file name is retrieved at the index 
		if (strcmp(current_filename, filename) == 0)
		{
			index_first = i;	//stores in the index in index_frist variable
			break;
		}

		i++;
	}

	if (index_first == -1)
	{
		return -1;
	}

	// Reset the directory entry for the deleted file and set them all to 0
	struct directory_entry entry = { 0 };

	directory[index_first] = entry;

	uint16_t current_blk_index = directory[index_first].first_current_blk_index;
	do {
		uint16_t next_block;
		//gets value of next block
		next_block = fat[current_blk_index].value;
		fat[current_blk_index].value = 0;	//set current index to 0
		current_blk_index = next_block;	//update blk index
	} while (current_blk_index != FAT_EOC);

	// Write the updated root directory and FAT to the disk
	if (block_write(sb->root_dir_index, directory) != 0)
	{
		return -1;
	}

	for (uint8_t i = 0; i < sb->fat_blocks; i++)
	{
		//pointer to FAT data that is written
		void *fat_data = &fat[i *(BLOCK_SIZE / sizeof(struct fat_entry))];
		if (block_write(i + 1, fat_data) != 0)
		{
			//writes data
			return -1;
		}
	}

	return 0;
}

int fs_ls(void)
{
	if (block_disk_count() < 0)
	{
		return -1;
	}

	printf("FS Ls:\n");

	// iterates over the directory entries and prints information about the existing files.
	for (int i = 0; i < FS_FILE_MAX_COUNT; i++)
	{
		if (directory[i].filename[0] != '\0')
		{
			char *filename = directory[i].filename;
			uint32_t size = directory[i].size;
			uint16_t data_block = directory[i].first_current_blk_index;
			printf("filename is: %s, size of file: %u, data_blk: %u\n", filename, size, data_block);
		}
	}

	return 0;
}

///////////////////

int fs_open(const char *filename)
{
	size_t filename_length = strlen(filename);
	if (block_disk_count() < 0 || (filename == NULL || (filename_length > FS_FILENAME_LEN - 1)))
	{
		return -1;
	}

	// Find an unused file descriptor
	int fd = -1;
	for (int i = 0; i < FS_OPEN_MAX_COUNT; i++)
	{
		if (open_files[i].used == 0)
		{
			fd = i;
			break;
		}
	}

	if (fd == -1)
	{
		return -1;
	}

	// Find the directory entry for the file
	int index_first = -1;
	int i = 0;
	int found = 0;	// 0 indicates false, 1 indicates true

	while (i < FS_FILE_MAX_COUNT && !found)
	{
		if (strcmp(directory[i].filename, filename) == 0)
		{
			index_first = i;
			found = 1;
		}

		i++;
	}

	if (index_first == -1)
	{
		fprintf(stderr, "Error: File '%s' not found\n", filename);
		return -1;
	}

	// Update the file descriptor
	open_files[fd].used = 1;
	open_files[fd].offset = 0;
	open_files[fd].first_directory_index = index_first;

	return fd;
}

int fs_close(int fd)
{
    //verifies the validity of file descriptor
	if (block_disk_count() < 0 || fd < 0 || fd >= FS_OPEN_MAX_COUNT || open_files[fd].used == 0)
	{
		fprintf(stderr, "Error: ");
		if (block_disk_count() < 0)
		{
			fprintf(stderr, "no disk is currently open\n");
		}
		else if (fd < 0 || fd >= FS_OPEN_MAX_COUNT)
		{
			fprintf(stderr, "FD not valid\n");
		}
		else
		{
			fprintf(stderr, "FD %d not in use\n", fd);
		}

		return -1;
	}

	open_files[fd].used = 0;

	return 0;
}

int fs_stat(int fd)
{
	if (block_disk_count() < 0 || fd < 0 || fd >= FS_OPEN_MAX_COUNT || open_files[fd].used == 0)
	{
		fprintf(stderr, "Error: ");
		if (block_disk_count() < 0)
		{
			fprintf(stderr, "no disk is currently open\n");
		}
		else if (fd < 0 || fd >= FS_OPEN_MAX_COUNT)
		{
			fprintf(stderr, "FD not valid\n");
		}
		else
		{
			fprintf(stderr, "FD %d not in use\n", fd);
		}

		return -1;
	}

	int index_first = open_files[fd].first_directory_index;
	return directory[index_first].size;
}

int fs_lseek(int fd, size_t offset)
{
	if (block_disk_count() < 0 || fd < 0 || fd >= FS_OPEN_MAX_COUNT || open_files[fd].used == 0)
	{
		fprintf(stderr, "Error: ");
		if (block_disk_count() < 0)
		{
			fprintf(stderr, "no disk is currently open\n");
		}
		else if (fd < 0 || fd >= FS_OPEN_MAX_COUNT)
		{
			fprintf(stderr, "FD not valid\n");
		}
		else
		{
			fprintf(stderr, "FD %d not in use\n", fd);
		}

		return -1;
	}

	int index_first = open_files[fd].first_directory_index;
	// checks if the given offset is greater than the size of FD
	if (offset > directory[index_first].size)
	{
		return -1;
	}

	open_files[fd].offset = offset;

	return 0;
}

int fs_write(int fd, void *buf, size_t count)
{
	uint8_t data_residing_in_disk[BLOCK_SIZE];

	if (block_disk_count() < 0 || fd < 0 || fd >= FS_OPEN_MAX_COUNT || open_files[fd].used == 0)
	{
		return -1;
	}

	int index_first = open_files[fd].first_directory_index;
	uint16_t current_blk_index = directory[index_first].first_current_blk_index;

	// Seek to the offset
	size_t block_offset = open_files[fd].offset % BLOCK_SIZE;
	size_t block_count = open_files[fd].offset / BLOCK_SIZE;

	while (block_count > 0 && current_blk_index != FAT_EOC)
	{
		current_blk_index = fat[current_blk_index].value;
		block_count = block_count - 1;
	}

	// Allocate new blocks if necessary
	size_t desired_block_count = count / BLOCK_SIZE;
	while (block_count < desired_block_count)
	{
		uint16_t fresh_current_blk_index = 0;
		for (uint16_t i = 0; i < sb->data_blocks; i++)
		{
			if (fat[i].value == 0)
			{
				fresh_current_blk_index = i;
				fat[i].value = FAT_EOC;
				break;
			}
		}

		if (fresh_current_blk_index == 0)
		{
			return -1;
		}

		// Update the FAT and directory entry
		if (current_blk_index == FAT_EOC)
		{
			directory[index_first].first_current_blk_index = fresh_current_blk_index;
		}
		else
		{
			fat[current_blk_index].value = fresh_current_blk_index;
		}

		current_blk_index = fresh_current_blk_index;
		block_count++;
	}


	// Write data to the disk blocks
	size_t bytes_written = 0;
	while (bytes_written < count)
	{
		// Read the block from disk if needed
		if (block_offset == 0)
		{
			if (current_blk_index == FAT_EOC)
			{
				uint16_t fresh_current_blk_index = 0;
				//iterates over FAT and looks for free data block
				for (uint16_t i = 0; i < sb->data_blocks; i++)
				{
					if (fat[i].value == 0)
					{
						fresh_current_blk_index = i;
						fat[i].value = FAT_EOC;
						break;
					}
				}

				if (fresh_current_blk_index == 0)
				{
					return -1;
				}

				// Update the FAT and directory entry
				if (current_blk_index == FAT_EOC)
				{
					directory[index_first].first_current_blk_index = fresh_current_blk_index;
				}
				else
				{
					fat[current_blk_index].value = fresh_current_blk_index;
				}

				current_blk_index = fresh_current_blk_index;
			}

			if (block_read(sb->data_block_start_index + current_blk_index, data_residing_in_disk) != 0)
			{
				return -1;
			}
		}

		// Write data to the block
		size_t amount_left = BLOCK_SIZE - block_offset;
		size_t data_write;
		if (amount_left < count - bytes_written)
		{
			data_write = amount_left;
		}
		else
		{
			data_write = count - bytes_written;
		}

		for (size_t i = 0; i < data_write; i++)
		{
			data_residing_in_disk[block_offset + i] = ((uint8_t*) buf)[bytes_written + i];
		}

		// Update metadata: the file descriptor offset, buf offset, and remaining bytes to read
		bytes_written = bytes_written + data_write;
		block_offset = block_offset + data_write;
		open_files[fd].offset = open_files[fd].offset + data_write;

		// Write the block back to disk if it's full
		if (block_offset == BLOCK_SIZE)
		{
			uint16_t current_block = sb->data_block_start_index + current_blk_index;

			if (block_write(current_block, data_residing_in_disk) != 0)
			{
				return -1;
			}

			block_offset = 0;
			current_blk_index = fat[current_blk_index].value;
		}
	}

	// Update the file size in the directory entry
	if (open_files[fd].offset > directory[index_first].size)
	{
		directory[index_first].size = open_files[fd].offset;
	}

	// Write the updated directory and FAT to the disk
	if (block_write(sb->root_dir_index, directory) != 0)
	{
		return -1;
	}

	//writes FAT content over to the disk
	for (uint8_t i = 0; i < sb->fat_blocks; i++)
	{
		uint8_t *fat_block_data = (uint8_t*) &fat[i *(BLOCK_SIZE / sizeof(struct fat_entry))];
		if (block_write(i + 1, fat_block_data) != 0)
		{
			return -1;
		}
	}

	return bytes_written;
}

int read_block(uint16_t current_blk_index, void *buf, size_t offset, size_t count)
{
	uint8_t data_residing_in_disk[BLOCK_SIZE];

	//iterates over FAT and updates the two variables
	while (offset >= BLOCK_SIZE && current_blk_index != FAT_EOC)
	{
		current_blk_index = fat[current_blk_index].value;
		offset = offset - BLOCK_SIZE;
	}

	size_t bytes_left_to_read = 0;
	//reads data from the file's data blocks and copies it into the buffer
	while (bytes_left_to_read < count && current_blk_index != FAT_EOC)
	{
		int result = block_read(sb->data_block_start_index + current_blk_index, data_residing_in_disk);
		if (result != 0)
		{
			return -1;
		}

		//stores amount of data remaining
		size_t amount_left = BLOCK_SIZE - offset;
		size_t bytes_to_read;
		if (amount_left < count - bytes_left_to_read)
		{
			bytes_to_read = amount_left;
		}
		else
		{
			bytes_to_read = count - bytes_left_to_read;
		}

		//copy the data from the data_residing_in_disk buffer into the buf buffer
		memcpy(buf + bytes_left_to_read, data_residing_in_disk + offset, bytes_to_read);

		bytes_left_to_read += bytes_to_read;
		offset = 0;

		if (bytes_left_to_read < count)
		{
			current_blk_index = fat[current_blk_index].value;
		}
	}

	return bytes_left_to_read;
}

int fs_read(int fd, void *buf, size_t count)
{
	if (block_disk_count() < 0 || fd < 0 || fd >= FS_OPEN_MAX_COUNT || open_files[fd].used == 0)
	{
		return -1;
	}

	int index_first = open_files[fd].first_directory_index;
	uint16_t current_blk_index = directory[index_first].first_current_blk_index;
	size_t offset = open_files[fd].offset;

	return read_block(current_blk_index, buf, offset, count);
}