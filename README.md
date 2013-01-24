avsocks 科学操长城软件  by avplayer.org 社区
=======


avsocks 科学操长城软件，由2部分构成，一个运行在能科学上网的服务器上，一个运行在不能科学上网的电脑上。
两个部分实际上为同一个可执行文件，都是  avsocks

在能科学上网的电脑上执行 avsocks -d ，加 -d 进入后台模式

在不能科学上网的电脑上执行 avsocks -d --avserver 能科学上网的电脑的名字或ip

好了，本地 4567 端口就开了 socks5 代理了。


萝莉们, 来看看我们是如何fuck墙的吧, 下面是工作示意图:

  
                  +---------------+     |     +-------------+
  browser/app --> | socks5 -> ssl | ----|---> | ssl -> sock |--> website/server
                  +---------------+     |     +-------------+
                                       GFW



# 编译

依赖 boost 和 openssl

备注: 在win32平台下编译应程序, 需要从 avplayer 项目中的 third_party 复制到源码所在目录, 就可以了.

