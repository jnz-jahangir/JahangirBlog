---
title: C++中STL容器总结
date: 2023-04-11 21:35:14
update: 
tags: [编程,语言]
catagories: 编程
---
# 前言
最近几周为了准备初赛，看了（~~看了就是学了😋~~）很多STL容器，但总觉得不是很系统，故写此博文进行总结。
# 1 不定长数组 $vector$
记得高中混OI的时候总听张巨佬提到什么向量，不定长数组之类的，总觉得是我学不会的很高级的东西，前段时间试图理解了一下，发现，~~啊，非常的简单~~，还是小小总结一下
## 1.1 特点
顾名思义，$vector$可以实现数组长度的变化，妈妈再也不用担心我爆栈啦
## 1.2 用法
### 1.2.1 定义
$vector$容器包含于$vector$头文件中，使用$vector$容器时，需要在文件头添加
```
#include<vector>
```
STL容器的定义都十分简洁美观  
```
vector<type> name;
```
其中，$type$填什么都可以，不论是C++标准数据类型，还是自定义数据类型（struct结构体）都可以塞进去，甚至可以套娃：  
```
vector<vector<type>> name;
```
显然，这是一个二维不定长数组，不过，你也可以让它部分不定长：  
```
vector<type> name[n];
```
（这个显然是本人拙劣的做法）
### 1.2.2 访问
$vector$有堪称完美的访问数据方式，即直接通过数组下标访问，简直完美符合*不定长数组*这一名称：
```
vector<int> vt;
...
cout<<vt[0];
```
当然，你不觉得麻烦也可以使用迭代器访问
```
vector<int> vt;
...
for(auto it=vt.begin();it!=vt.end();it++)
{
    cout<<*it;
}
```
这里需要注意的是，迭代器类型实际上是``vector<int>::iterator``，这里写作auto纯属偷懒。  
但是，在DevCpp等版本较老的IDE中，似乎不支持auto定义迭代器（至少我写的时候会报错）  
另外，STL容器的``end()``方法返回的是容器末尾，而末尾是没有有效值的，若执行以下代码，将会RE（$Runtime Error$）：
```
vector<int> vt;
vt.push_back(1);
cout<<*vt.end();
```
只有在$vector$容器中，迭代器可以加减一个数字：
```
vector<int> vt;
vector<int>::iterator it;
for(int i=1;i<=10;i++)
    vt.push_back(i);
for(it=vt.begin();it!=vt.end();it=it+1)
    cout<<*it;
```
而在其他容器中，对迭代器加减一个数字是**非法**的，只能对其进行自加减（***it++ & it--***）
### 1.2.3 常用方法
- push_back()
```
void std::vector<int>::push_back(const int &__x)
```
顾名思义，向$vector$容器末尾添加一个元素
- pop_back()
```
void std::vector<int>::pop_back()
```
从$vector$容器末尾弹出一个元素
- size()
```
std::size_t std::vector<int>::size()
```
获取$vector$容器元素个数  
注意，$vector$容器的下标是从***0***开始的，因此，执行以下代码会RE：
```
vector<int> vt;
vt.push_back(1);
cout<<vt[vt.size()];
```
- clear()
```
void std::vector<int>::clear()
```
顾名思义，清空$vector$容器中所有元素  
*注意：该方法时间复杂度为O(N)*
- insert()
```
insert(__position,__x);
```
和其他容器不一样，$vector$的``insert()``方法是向指定位置插入数据，其中，``__position``类型为
``vector<type>::iterator``，即迭代器，``__x``类型为$vector$容器数据的类型
```
vector<int> vt;
vector<int>::iterator it;
for (int i=1;i<=10;i++)
    v.push_back(i);
it=vt.begin();
v.insert(it+2,6);
```
上述代码实现了将6插入到$vt[2]$的位置，原有元素将顺次后移
- erase()
```
erase(__position);
```
与``insert()``类似，使用迭代器删除指定位置的元素，其后元素顺次前移
```
erase(__positionBegin,__positionEnd);
```
即是删除[ __positionBegin,__positionEnd )区间内的元素  
***注意是左闭右开区间***
## 1.3 用途
### 1.3.1 使用数组浪费大量空间
