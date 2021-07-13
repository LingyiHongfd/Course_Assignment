# 附加题说明

### 编译challenge.c
gcc challenge.c -o challenge

### 题目要求
challenge.c 会读取环境变量"PWD"(当前路径,如"/home/seed/env_lab"), 然后将其中的值传给buffer. 由于程序使用了危险的函数"strcpy", 因此如果"PWD"的长度过长，会在栈上造成溢出. 本题需要大家通过栈溢出将buffer上面的数组overflowIt的一个位置的值修改成0x01020304. 
如果攻击成功，程序会输出"Congratulations, you pwned it!".

### 提示
1. 需要创建新的文件夹, 可能需要GDB调试.
2. 如果下课前半小时没有完成，可以找助教要一个方便调试的pwn脚本.