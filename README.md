# Reversing the ESPecter bootkit (non-uefi, only mbr part for now)

## The Infector

### The main function

Seems we get an non-packed payload. The main function looks like this:

![image-20220111113132837](README.assets/image-20220111113132837.png)

First, a function is called to decide if  we're a Wow64 process (running on a 64bit system) or not. The patch_disk function is only called if we're on a real 32bit PC. Looks like **this is a 32 bit version of this bootkit**.

### Checking whether we're in 32bit

This is done via the `IsWow64Process` API which is resolved dynamically from a handle to kernel32:

![image-20220111113513439](README.assets/image-20220111113513439.png)

### Obtaining a handle to the disk device

First thing is, a handle is acquired to the disk device.

![image-20220111114044173](README.assets/image-20220111114044173.png)

This is first attempted by parsing some registry values to get the device name and using CreateFileA on that.

![image-20220111114250034](README.assets/image-20220111114250034.png)

The key is `"SYSTEM\CurrentControlSet\services\Disk\Enum\0"` and it's appended the UUID `{53f56307-b6bf-11d0-94f2-00a0c91efb8b}`. This UUID is `GUID_DEVINTERFACE_DISK`. According to MSDN : `The system-supplied storage class drivers register an instance of GUID_DEVINTERFACE_DISK for a hard disk storage device`. Seems like it's maybe trying to get a handle to a storage device driver responsible for that disk. Anyway, it's purpose is clear and not very interesting.

If the handle cannot be obtained using this method, it tries to obtain a handle to `"\\\\.\\PhysicalDrive0"`

![image-20220111114725396](README.assets/image-20220111114725396.png)

### Sanity testing the MBR

After the handle is obtained it does a sanity test on the first sector. It makes sure the first two bytes of it are non-null.

It first reads 0x200 (512 - sector size) from the disk device handle to the stack.

![image-20220111115023742](README.assets/image-20220111115023742.png)

And makes sure the first two bytes are non-null (bl is zeroed here).

![image-20220111115112875](README.assets/image-20220111115112875.png)

Zero as a return value is actually a success indicator here:

![image-20220111115229300](README.assets/image-20220111115229300.png)

Perhaps the function signature is something like `bool is_mbr_broken(HANDLE hDevice)`. (That way a return value of `true` indicates an error).

### Backup beep.sys

The driver `C:\Windows\System32\drivers\beep.sys` is copied to `C:\Windows\Help\intel.chm`.

This maybe a hint to it being infected in the future.

![image-20220111122652247](README.assets/image-20220111122652247.png)

### Writing the encrypted configuration

First, it writes some resource I couldn't figure out to physical 0x800 (5th sector, one-counted).

![image-20220111115600697](README.assets/image-20220111115600697.png)

This resource is obtained from the mapped PE in the process address space:

![image-20220111115654207](README.assets/image-20220111115654207.png)



After further checking online this is actually the encrypted configuration file.

### Writing driver payload

Next, It decrypts the kernel mode driver payload: 

![image-20220111115758334](README.assets/image-20220111115758334.png)

And writes it to physical 0xA00 (6th sector, one-counted)

### Backing up the MBR

It then backs up the MBR.

Before doing that it first checks whether the MBR is already backed up in the second sector.

It reads the first sector (MBR), and the second one (maybe already backed up MBR)

![image-20220111120131204](README.assets/image-20220111120131204.png)

![image-20220111120139847](README.assets/image-20220111120139847.png)

And then passes both of these buffers to the function checking if the backup already exists:

![image-20220111120222569](README.assets/image-20220111120222569.png)

The function looks like this:

![image-20220111120237209](README.assets/image-20220111120237209.png)

To check if the mbr is already backed successfully up it checks the following:

1. The first sector (MBR) does not start with 0x33. This is because the normal windows bootloader will start with 0x33:

![image-20220111120507110](README.assets/image-20220111120507110.png)

2. If the MBR indeed does not start with 0x33 (an indicator that is was already overwritten by the bootkit) it checks that the backup was done successfully by verifying that it ends with 0xaa. (because 0xaa55 is the signature for a bootable driver and an MBR is always terminated with it).
3. The second sector (potential original mbr backup) should start with 0x33 (because it's a backup of the original).
4. The second sector should end with 0xaa (as stated before - bootable sector signature).

If the mbr is not already backed up it reads 0x200 bytes from offset 0x0 (reads the MBR).

![image-20220111121224076](README.assets/image-20220111121224076.png)

(notice the second sector buffer is now reused as the new MBR buffer)

And writes the original MBR to the second sector:

![image-20220111121306950](README.assets/image-20220111121306950.png)

### Overwrite mbr and some other stuff

First, it checks the os version and depending on it loads different resources:

![image-20220111121725442](README.assets/image-20220111121725442.png)

It also decrypts the new MBR in the process.

It then copies parts of the original MBR over the new mbr:

![image-20220111121831797](README.assets/image-20220111121831797.png)

These functions look like so:

![image-20220111122029271](README.assets/image-20220111122029271.png)

They read the original MBR, take it at an offset and copy that offset over the new MBR at certain offsets.

The 3 payloads are then written to the disk:

1. The MBR at physical 0x0 (1st sector, one-counted):

   ![image-20220111122226511](README.assets/image-20220111122226511.png)

2. The second payload at physical 0x400 (3rd sector, one-counted):

   ![image-20220111122329664](README.assets/image-20220111122329664.png)

3. The third payload at physical 0x600 (4th sector, one-counted):

   ![image-20220111122340823](README.assets/image-20220111122340823.png)



The disk looks like this:

![image-20220111122515977](README.assets/image-20220111122515977.png)

## The new MBR

### Debugging the boot process

I wanted to get debugging functionality on the new MBR so I created a 32bit windows  VMware machine.

Then I changed the VMX file:

![image-20220111155424077](README.assets/image-20220111155424077.png)

And in IDA pressed Debugger->Attach->Remote GDB Process and entered localhost::8832 as the address:

![image-20220111155532252](README.assets/image-20220111155532252.png)

Great. Now let's debug this shit.

### Boilerplate and backups

The first things to execute are the following instrucitons:

![image-20220111162023902](README.assets/image-20220111162023902.png)

They clean the stack segment, save the the old sp in 0x7bfe and set sp to point to there (sort of like a push old sp after setting the new sp).

![image-20220111162132962](README.assets/image-20220111162132962.png)

Afterwards the ds segment is cleared, all general purpose registers are pushed and the direction flag is cleard.

### Memory region setup

![image-20220111163153526](README.assets/image-20220111163153526.png)

Now this is a little more complicated.

From looking online we can see that 00:0x413 contains the size of free memory from the bottom of memory until EBDA in units of 2KBs. 

![image-20220111163431676](README.assets/image-20220111163431676.png)

BIOS memory map:

![image-20220111163459511](README.assets/image-20220111163459511.png)

This size is subtracted by 2 (decreased by 2KBs), updated and then placed multiplied by 64 in es. Because EBDA is reserved the es register is placed after the bootsector and some space before the EBDA to allow usage of some free memory.

An interesting anecdote:

INT 12H does exactly (reads a word at 00:0x413) this when returning the memory size in KBs. I wonder why the author didn't use that API and if he knew about it:

![image-20220111163815200](README.assets/image-20220111163815200.png)



![image-20220111163855516](README.assets/image-20220111163855516.png)

This memory indeed looks like it's nulled:

![image-20220111164904850](README.assets/image-20220111164904850.png)

It then copies It's own first 0x200 first bytes (the whole MBR = 0x100 * sizeof(word)) to that free memory blob. (copies from ds:esi to es:edi)

![image-20220111163942110](README.assets/image-20220111163942110.png)

![image-20220111164138011](README.assets/image-20220111164138011.png)

And reads two sectors from after the backed up MBR to immediately after the copied MBR to before the EBDA.

![image-20220111210157418](README.assets/image-20220111210157418.png)

So now the memory layout before the EBDA looks like so:

```
[EBDA - 0x2000] -> Malicious MBR
[EBDA - 0x1800] -> Sector 2 (0-counted)
[EBDA - 0x1600] -> Sector 3
[EBDA - 0x1400] -> NULL padding
[EBDA] -> EBDA (BIOS reserved)
```

These newly loaded bytes are then decrypted:

![image-20220111210658170](README.assets/image-20220111210658170.png)

The decryption works the following way:

```python
for byte in encrypted: # len(encrypted) == 0x400
    if byte != 0:
        byte = (byte - 0x4d) ^ 0x42
    decrypted.append(byte)
```

### Hooking INT 13

Then, INT 13 is hooked:

![image-20220111211107777](README.assets/image-20220111211107777.png)

Why does this hook INT13?

If we take a look again at the BIOS memory map:

![image-20220111163459511](README.assets/image-20220111163459511.png)

This snippit replaces the value at 00:0x4c with a far jump to es:0x94 (where es is a segment that points to the start of the copied bootloader at the free allocated memory).

As we can see, 0x4c is where INT 13 is located:

![image-20220111173745243](README.assets/image-20220111173745243.png)

It then saves the old INT 13 ISR far pointer in the middle of the copied bootloader code!

It's actually copied to the middle of the following far jump instruciton:

![image-20220111211935413](README.assets/image-20220111211935413.png)

Which we will get to right now:

### The INT 13 Hook

Let's analyze the hook handler itself:

![image-20220111212536591](README.assets/image-20220111212536591.png)

Looks like the hooked interrupt handler does something significant only if ah == 0x2 || ah == 0x42. These two function codes are for reading the disk.

If the function code (ah) is not relevant, the far jump is taken. If you remember from the last section, this far jump was earlier overwritten to point to the original INT 13 handler.

If the function code is relevant, the jump is followed and the following happens:

![image-20220111213029391](README.assets/image-20220111213029391.png)

The value of ah (function code) is patched once again inside future code (which we will get to shortly) and a call to the original INT13 is made.

Some less interesting stuff happens:

![image-20220111213205574](README.assets/image-20220111213205574.png)

If eax is 0x42, some conversion between the function codes happens (presumably INT13, AH=0x42 is similar to INT13, AH=0x2) and if al (number of sectors read) is negative or zero it's incremented.

Now, we enter some setup code:

![image-20220111213445628](README.assets/image-20220111213445628.png)

cx equals al (contains amount of sectors read - returned by the original interrupt call) times 0x200 (sizeof sector). bx contains the target buffer (as passed to the interrupt) and is moved to di.

This is the real 'meat' of the INT 13 hook:

![image-20220111213711896](README.assets/image-20220111213711896.png)

We search for a pattern of bytes in the bytes read from disk and if we match it we replace it with some bytes of our own. This is likely code or function pointers to get control flow in a later stage in the boot process.

Note: some data is actually replaced with cs:0x200 which is calculated dynamically according to the value of CS. After placing a breakpoint we can see this will actually points to the start of the first sector decrypted in memory after our copied malicious MBR.

### Executing the original backed up MBR

After the INT 13 hook, the following far jump is made, to jump into the copied bootloader (until now we were executing around 0x7c00 the place where the bootloader was originally placed.)

![image-20220111212304357](README.assets/image-20220111212304357.png)

The original backed up MBR is then read into 0x7c00:

![image-20220111212408069](README.assets/image-20220111212408069.png)

And a far jump is preformed to the normal windows bootloader.

![image-20220111212446963](README.assets/image-20220111212446963.png)

## The Driver