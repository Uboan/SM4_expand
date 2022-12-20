执行以下命令
mkdir build
cd build 
cmake ..
make




然后生成可执行文件如下：

TEM 测试SM4-256-EM（单分组）的性能
TLM 测试SM4-256-LM（单分组）的性能
TECB 测试SM4-128和SM4-256 4个方案的（单分组）性能对比

TCBC 测试SM4-256-LM的CBC性能
TECBC 测试SM4-256-EM的CBC性能
TSM4CBC 测试SM4-128的CBC性能

TCTR 测试SM4-256-LM和EM的CTR性能
TGCM 测试SM4-256-LM和EM的GCM和SM4-128 GCM的性能


