# IORI_Loader - Bypass EDRs
![iori](https://user-images.githubusercontent.com/110354855/198591145-8688c68d-cc21-44bc-b7ec-0dd2f4f40688.png)

## Description  
FUD advanced Loader implementing dynamic indirect syscall with syscall number and syscall instruction Unhooking with Halosgate technic. Shellcode in UUIDs format to avoid static analysis, syscall instructions and syscall number don't exist in the binary opcode which makes it avoid static analysis and they get resolved at run time. also it gets the API addresses from the PEB by offsets and the comparison is done by hashing.

## Credits / References
[@smelly__vx](https://twitter.com/smelly__vx) & [@am0nsec](https://twitter.com/am0nsec) ( Creators/Publishers of the Hells Gate technique )
* https://github.com/am0nsec/HellsGate
* [The Original Paper](https://vxug.fakedoma.in/papers/VXUG/Exclusive/HellsGate.pdf)  

Reenz0h from [@SEKTOR7net](https://twitter.com/SEKTOR7net) (Creator of the HalosGate technique )
* https://blog.sektor7.net/#!res/2021/halosgate.md



