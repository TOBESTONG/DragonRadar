# DragonRadar - kernel fuzzer

DragonRadar is a fuzzing framework designed for the Kata-specific kernel via Kata’s built-in Dragonball. 
DragonRadar implements an adapter layer for Dragonball, enabling developers to easily leverage the popular Syzkaller kernel fuzzing framework to test custom Kata kernel features under realistic operational scenarios. 

DragonRadar is designed with reference to Syzkaller, one of the most widely-used kernel testing tools.


## Documentation
Please refer to the following documentation on how to make DragonRadar available and use it:

- [How to install DragonRadar](docs/setup.md)
- [How to use DragonRadar](docs/usage.md)
  
For information on how to use Kata container’s built-in Dragonball, please refer to the code repository at 
- [How to boot Dragonball](https://github.com/openanolis/dbs-cli)

## Evaluation
Regarding the experimental part of the data, we put the bugs found by DragonRadar on the kernel in the dates/crashes folder.

