# 02_known

## Code Analysis

```c
void entry(void)

{
  bool bVar1;
  undefined3 extraout_var;
  char password_buf [8];
  DWORD num_read;
  HANDLE stdin_handle;

  password_buf._0_4_ = 0;
  password_buf._4_4_ = 0;
  stdin_handle = GetStdHandle(STD_INPUT_HANDLE);
  stdout_handle = GetStdHandle(STD_OUTPUT_HANDLE);
  SetConsoleTextAttribute(stdout_handle,0xce);
  WriteConsoleA(stdout_handle,s_**********_Attention!_**********_00403000,0x70a,(LPDWORD)0x0,
                (LPVOID)0x0);
  ReadConsoleA(stdin_handle,password_buf,8,&num_read,(PCONSOLE_READCONSOLE_CONTROL)0x0);
  bVar1 = main(password_buf);
                    /* WARNING: Subroutine does not return */
  ExitProcess(CONCAT31(extraout_var,bVar1));
}
```

The unlock program sets up the stdin, stdout handles, asks for a password of
length 8, then passes this to the main function.

```c
bool __cdecl main(char *password)

{
  BOOL BVar1;
  DWORD DVar2;
  _WIN32_FIND_DATAA local_194;
  char fname_buf [64];
  int fname_len;
  HANDLE local_c;
  uint num_files;

  num_files = 0;
  BVar1 = SetCurrentDirectoryA(s_Files_00403758);
  if (BVar1 == 0) {
    fail(s_SetCurrentDirectory("Files")_00403738);
  }
  local_c = FindFirstFileA(s_*.encrypted_0040372c,(LPWIN32_FIND_DATAA)&local_194);
  if (local_c == (HANDLE)0xffffffff) {
    fail(s_FindFirstFile_0040371c);
  }
  while( true ) {
    do {
                    /* iterate over all files matching glob *.encrypted */
      fname_len = strcpy(fname_buf,local_194.cFileName);
      local_194.cAlternateFileName[fname_len + 6] = '\0';
      decrypt_file(local_194.cFileName,fname_buf,password);
      num_files += 1;
      BVar1 = FindNextFileA(local_c,(LPWIN32_FIND_DATAA)&local_194);
    } while (BVar1 != 0);
    DVar2 = GetLastError();
    if (DVar2 == 0x12) break;
    fail(s_FindNextFile_0040370c);
  }
  FUN_00401160(num_files);
  return num_files != 0;
}
```

The main function has a loop to iterate over all files in the `Files` folder
matching the glob `*.encrypted`. Then a copy of the file's name is made with
required modification to remove the `.encrypted` suffix and both the original
name found, it's copy and the password are passed to the `decrypt_file`
function

```c
void __cdecl decrypt_file(LPCSTR enc_fname,LPCSTR copied_fname,char *password)

{
  BOOL BVar1;
  char buf [8];
  DWORD local_14;
  HANDLE enc_file_handle;
  HANDLE dec_file_handle;
  DWORD bytes_read;

  enc_file_handle =
       CreateFileA(enc_fname,GENERIC_READ,1,(LPSECURITY_ATTRIBUTES)0x0,3,0x80,(HANDLE)0x0);
  if (enc_file_handle == (HANDLE)0xffffffff) {
    fail(enc_fname);
  }
  dec_file_handle =
       CreateFileA(copied_fname,GENERIC_WRITE,0,(LPSECURITY_ATTRIBUTES)0x0,2,0x80,(HANDLE)0x0);
  if (dec_file_handle == (HANDLE)0xffffffff) {
    fail(copied_fname);
  }
  while( true ) {
                    /* read from enc_file, 8 bytes at a time, decrypt them, then write to output
                       buffer */
    BVar1 = ReadFile(enc_file_handle,buf,8,&bytes_read,(LPOVERLAPPED)NULL);
    if (BVar1 == 0) {
      fail(enc_fname);
    }
    if (bytes_read == 0) break;
    decrypt_buf(buf,password);
    BVar1 = WriteFile(dec_file_handle,buf,bytes_read,&local_14,(LPOVERLAPPED)NULL);
    if (BVar1 == 0) {
      fail(copied_fname);
    }
  }
  CloseHandle(dec_file_handle);
  CloseHandle(enc_file_handle);
  bytes_read = FUN_00401000((int)enc_fname);
  copied_fname[bytes_read - 10] = '\n';
  WriteConsoleA(stdout_handle,enc_fname,bytes_read,(LPDWORD)0x0,(LPVOID)0x0);
  WriteConsoleA(stdout_handle,&DAT_00403760,4,(LPDWORD)0x0,(LPVOID)0x0);
  WriteConsoleA(stdout_handle,copied_fname,bytes_read - 9,(LPDWORD)0x0,(LPVOID)0x0);
  return;
}

```

This function then opens the encrypted file for reading and the suffix removed
copy for writing. It has a loop which reads at most 8 bytes from the encrypted
file, decrypts it using the `decrypt_buf` function which is passed this data
along with the previously supplied password.

```c
void __cdecl decrypt_buf(char *param_1,char *password)

{
  byte bVar1;
  uint i;

  i = 0;
  while (bVar1 = (byte)i, (char)bVar1 < 8) {
    param_1[i] = ((param_1[i] ^ password[i]) << (bVar1 & 7) |
                 (byte)(param_1[i] ^ password[i]) >> 8 - (bVar1 & 7)) - bVar1;
    i = (uint)(byte)(bVar1 + 1);
  }
  return;
}
```

This function just uses simple xor, rol and subtract operations to decrypt the data.

## Solution

We need the password to decrypt all the files. Since the decryption is 8 byte
based, easily reversible / brute forceable, we can do a known plaintext attack
easily. To do this, atleast 8 consecutive bytes of plaintext are needed. We
can use the 8 byte fixed header of the `png` file format shown
[here](https://en.wikipedia.org/wiki/Portable_Network_Graphics#File_header).

Thus the 8 byte sized fixed png header can used to find out the password. The
simpler approach was brute-forcing for such a small password \(len = 8\)

```python
p8 = lambda x : bytes([x & 0xff])

png_header = bytes.fromhex("89504e470d0a1a0a")

def get_password() -> bytes:
    with open('./Files/capa.png.encrypted', "rb") as h:
        enc_header = h.read(8)
    out = b""
    for i, (v1, v2) in enumerate(zip(enc_header, png_header)):
        for b in range(256):
            tmp = b ^ v1
            tmp = (((tmp << i) | (tmp >> (8 - i))) - i) & 0xff
            if tmp == v2:
                out += p8(b)
                break

```

This gives password as:

> `No1Trust`

This can then be used, just by running the given binary or by replicating the logic in python

## flag

> `You_Have_Awakened_Me_Too_Soon_EXE@flare-on.com`

