# MBR Loader
A custom IDA Pro loader script for analyzing and processing Master Boot Record (MBR) binaries. This loader identifies MBR files, sets up the appropriate memory segments, and defines critical structures like the partition table entries. It also annotates the binary with useful metadata for easier analysis.

## Features  
- **MBR Signature Validation**: Ensures the binary file contains the correct MBR signature (0x55AA).  
- **Automatic Segment Setup**: Configures the MBR binary as a 16-bit code segment starting at address `0x7C00`.  
- **Partition Table Parsing**: Defines and applies the `PARTITION_TABLE_ENTRY` structure to the four partition table entries.  
- **Signature Annotation**: Adds a comment to the MBR signature (last two bytes of the MBR).  
- **Easy Debugging**: Prints helpful messages for structure definitions and partition entry setup.  

## Installation  
1. Save the loader Python file to your `<IDA Directory>/loaders` folder.  
2. Restart IDA Pro to make the loader available.  

## Usage  
1. Open IDA Pro.  
2. Load an MBR binary file (at least 512 bytes).  
3. If the file is valid, the loader will process it automatically and present the following features:  
   - A 16-bit code segment (`seg0`) starting at `0x7C00`.  
   - Four parsed and structured partition table entries.  
   - A comment on the last two bytes indicating the MBR signature.  

## Partition Table Structure  
The loader defines a structure for the partition table entries with the following fields:  

| **Field Name**       | **Offset** | **Size**   | **Description**                                                       |  
|-----------------------|------------|------------|------------------------------------------------------------------------|  
| `boot_indicator`      | 0x00       | 1 byte     | Boot indicator: `0x00` = inactive, `0x80` = bootable (active).         |  
| `starting_head`       | 0x01       | 1 byte     | Starting head of the partition.                                       |  
| `starting_sector`     | 0x02       | 1 byte     | Starting sector (bits 6-7 are part of the cylinder value).             |  
| `starting_cylinder`   | 0x03       | 1 byte     | Starting cylinder.                                                    |  
| `partition_type`      | 0x04       | 1 byte     | Partition type or system ID.                                          |  
| `ending_head`         | 0x05       | 1 byte     | Ending head of the partition.                                         |  
| `ending_sector`       | 0x06       | 1 byte     | Ending sector (bits 6-7 are part of the cylinder value).               |  
| `ending_cylinder`     | 0x07       | 1 byte     | Ending cylinder.                                                      |  
| `starting_lba`        | 0x08       | 4 bytes    | Starting Logical Block Address (LBA) of the partition.                |  
| `total_sectors`       | 0x0C       | 4 bytes    | Total number of sectors in the partition.                             |  

## Requirements  
- **IDA Pro Version**: 7.6 (recommended for compatibility).  
- **Binary File**: A valid MBR binary file of at least 512 bytes.  

## Limitations  
- The loader assumes the MBR starts at `0x7C00` and is loaded in a 16-bit environment.  
- Works only with valid MBR files containing the 0x55AA signature.  