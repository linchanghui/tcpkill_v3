1.实现双向发送fin|ack包
2.实现根据netstat -p检测是否真的关闭
3.运行命令tcpkill -i lo -s 127.0.0.1 -t 12001 -d 127.0.0.1 -k 56736
-i 网卡
-s 源ip
-t 源端口
-d 目标ip
-k 目标端口