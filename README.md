# 基于NTQQ实现的防撤回

原理可见 [ntrecall](https://napneko.github.io/other/ntrecall)

## 适配对象
Windows QQ 9.9.19 34740 已测试

## 使用介绍

1. 下载release压缩包
2. 解压将两个文件丢进QQ.exe所在的QQ目录
3. 为NapCatBootMain.exe 建立桌面快捷即可
4. 双击快捷方式
5. 叉掉黑色窗口

## 优点
1. 无消息数量约束 持久化拦截
2. 图片/文件下载不会在撤回后失败
3. 检测特征极少 启动后会进程分离同时取消注入dll 唯一残留patch
4. 不影响正常QQ使用

## 缺点
1. 适配版本少
2. 易出现崩溃
3. 检测只是少不是完全过掉

## 提示
代码为了快速迭代与方便 写法较为抽象

此应用衍生自NapCatQQ周边设施