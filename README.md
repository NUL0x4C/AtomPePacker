### AtomPePacker : A Highly Capable Pe Packer
<br>

### Features :
- the packer only support x64 exe's (altho planning to make x32 version but idk when it'll be done)
- no crt imports
- api hashing library ( custom getmodulehandle and getprocaddress )
- direct syscalls ( for the part that i do the ntdll unhooking )
- ntdll unhooking from \KnownDlls\
- support tls callbacks
- support reallocation in case of needed ( the image is mapped to the preferable address first )
- no rwx section allocation 
- support exception handling
- uses elzma compression algorithm to do the compression (reducing the final exe size)
- its local run pe, so it support arguments 
- fake imported functions to add more friendly look to the iat 



<br>


### Builder :
- supports only 1 input: `x64 native exe files.`
- supports 3 outputs:
  - dll :
    - `Example "rundll32.exe DllPP64.dll Atom" (Using "Atom" is a must to run your payload - this is the name if the exported function in the dll)` 
    - `can be hijacked / injected into other process`
  - exe :
    - `this output is the default (with console - for binaries like mimikatz)`
  - no console exe
    - `for binaries like a c2 agent`


<br>

### Usage :
```

[#] Usage  : PePacker.exe <Input x64 exe> <*Output*> <*Optional Features*>
[#] Output :
              -d : Output The Packed Pe As A x64 Dll File
              -e : Output The Packed Pe As A x64 Exe File (Default)
[#] Features :
              -h : Hide The Console - /SUBSYSTEM:WINDOWS



Example:


PePacker.exe mimikatz.exe			: generate exe packed file
PePacker.exe mimikatz.exe -e			: generate exe packed file
PePacker.exe mimikatz.exe -e	-h		: generate hidden exe packed file
PePacker.exe mimikatz.exe -d			: generate dll output

```




<br>

### Demo - Builder :
![Screenshot 2022-10-12 073947](https://user-images.githubusercontent.com/111295429/195252422-8e950ea8-be59-406d-ab6e-42bf273ae314.png)
![Screenshot 2022-10-12 074128](https://user-images.githubusercontent.com/111295429/195252144-1c32c279-2e22-4ccd-8b06-6b2aac901324.png)



<br>
<br>

### Demo - Profit :
![photo_2022-10-12_07-08-33](https://user-images.githubusercontent.com/111295429/195249176-9c021c71-5c1c-42f7-b1fa-7937259e6e39.png)
![photo_2022-10-12_07-08-38](https://user-images.githubusercontent.com/111295429/195249100-1fe2a944-c67f-4495-b20f-8062afe6a429.jpg)


### TODO:
  - x32 support
  - reducing the entropy





