chainer c++ v0.31

目前扫描速度很快 你从没见识过的那种 （反正非常快就是了)
只写了格式化 因为没啥时间 毕竟我开源也没钱赚
有时间再完善

有bug可以告诉我
qq:0x86EC35B0

当然你也可以自己写membase用内核实现 (本来想写再有个基类继承 但懒得写了) 直接照着membase写就完了 或许你需要再改些其他的 随便吧

当然此版本有过缺页 看search<T>::get_pointers函数注释 自己理解 不会就算

当然  此版本也可查找两地址之间的指针链 
{
    for (auto m : memtool::extend::vm_static_list)
        m->filter = true;
    
    auto mod = new vm_static_data(0, 100); // 起止地址
    strcpy(mod->name, "dizhi1"); // 随便起的
    vm_static_list.emplace(mod); // 这样就行了
}

main.cpp仅为基本演示 你可以自己改 反正开源

如果获取pid有问题的话 自己写数字吧 嗯

用termux之类的install cmake
然后自己编译
(cd 目前路径
mkdir build
cd build
cmake ..
make -j8
)