## 使用方式

本项目为BUAA计网实验提高层次作业，基于Python3.12在Linux平台开发。理论上，由于使用了类型提示语法和Linux系统调用，能够适配安装Python3.8以上环境的Linux各个版本。

## 具体流程

1. 在有正确python环境（大于3.8版本）的Linux下，使用pip install -r requirements.txt安装依赖。
2. 编辑config.yaml配置文件，设置routerid、areaid、加入OSPF的网卡名称（与linux系统中对网卡的命名一致）。目前不限制加入的网卡数量。
3. 使用sudo python ./start.py启动ospf。注意，该操作会阻塞pip进程，因此如果需要作为服务运行，需要配置linux相关设置来以服务的方式启动。

> Sudo权限用于设置网卡模式为混杂模式、打开网卡自动转发、创建原始套接字。

## 局限性

1. 仅实现以太网广播interface，不过对于通用linux而言，也仅会用到以太网广播接口。
2. 未实现lsa的老化重传，尚不适用于长时间作为主力路由运行，适合用于学习交流、短期调试。
3. 目前仅实现了单area下的ospf协议。

## 调试方法

* 默认启动了debug级别的log，可以通过log查看内部运行细节。
* 在命令行快速输入`lsdb`可以查看目前的lsdb。
* 在命令行快速输入`cal`可以立即计算路由表，并输出下一条计算结果。
