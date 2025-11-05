---
title: java反射机制
published: 2025-11-06
description: ''
image: ''
tags: [学习笔记]
category: 'Android'
draft: false 
lang: ''
---
> 本文为加固前置知识

# 0、什么是反射

不知道的时候我以为这是一种映射关系

实则不然，**反射**是指在程序运行时动态地获取类的信息，包括类名、字段、方法等，从而操作类或对象的属性和方法。本质是JVM得到class对象之后，**再通过class对象进行反编译，从而获取对象的各种信息**

**为什么需要了解反射**

Java属于先编译再运行的语言，程序中对象的类型在编译期就确定下来了，而当程序在运行时可能需要**动态加载**某些类，这些类因为之前用不到，所以没有被加载到JVM。通过反射，可以在运行时动态地创建对象并调用其属性，**不需要提前在编译期知道运行的对象是谁。**

可以理解为反射其实就是直接使用类的一个逆向使用

# 1、举个🌰

```java
// 来自博客园-陈树义

public class Apple {

    private int price;

    public int getPrice() {
        return price;
    }

    public void setPrice(int price) {
        this.price = price;
    }

    public static void main(String[] args) throws Exception{
        //正常的调用
        Apple apple = new Apple();
        apple.setPrice(5);
        System.out.println("Apple Price:" + apple.getPrice());
        //使用反射调用
        Class clz = Class.forName("com.chenshuyi.api.Apple");
        Method setPriceMethod = clz.getMethod("setPrice", int.class);
        Constructor appleConstructor = clz.getConstructor();
        Object appleObj = appleConstructor.newInstance();
        setPriceMethod.invoke(appleObj, 14);
        Method getPriceMethod = clz.getMethod("getPrice");
        System.out.println("Apple Price:" + getPriceMethod.invoke(appleObj));
    }
}
```

从代码中可以看到我们使用反射调用了 setPrice 方法，并传递了 14 的值。之后使用反射调用了 getPrice 方法，输出其价格。上面的代码整个的输出结果是：

```undefined
Apple Price:5
Apple Price:14
```

从这个简单的例子可以看出，一般情况下我们使用反射获取一个对象的步骤：

- 获取类的 Class 对象实例

```java
Class clz = Class.forName("com.zhenai.api.Apple");
```

- 根据 Class 对象实例获取 Constructor 对象

```java
Constructor appleConstructor = clz.getConstructor();
```

- 使用 Constructor 对象的 newInstance 方法获取反射类对象

```java
Object appleObj = appleConstructor.newInstance();
```

而如果要调用某一个方法，则需要经过下面的步骤：

- 获取方法的 Method 对象

```cpp
Method setPriceMethod = clz.getMethod("setPrice", int.class);
```

- 利用 invoke 方法调用方法

```cpp
setPriceMethod.invoke(appleObj, 14);
```

到这里，我们已经能够读反射的基本使用。但如果要进一步掌握反射，还需要对反射的常用 API 进行理解

# 2、反射常用API

> 参考东方玻璃大佬

在JDK中，主要由以下类来实现Java反射机制，**这些类都位于java.lang.reflect包中**

- Class类：代表一个类
- Constructor 类：代表类的构造方法
- Field 类：代表类的成员变量(属性)
- Method类：代表类的成员方法

在JDK中，反射相关的 API 可以分为下面几类：获取反射的 Class 对象、通过反射创建类对象、通过反射获取类属性方法及构造器。

## 反射获取Class

在反射中，要获取一个类或调用一个类的方法，我们首先需要获取到该类的 Class 对象。

- 非动态加载时,可通过`.class`属性或实例`.getClass()`方法获取Class类

- 动态加载时,可使用`Class.forName()`和`ClassLoader.loadClass()`加载并获取类对象

```java
//1. 获取类对象
// 动态加载
Class<?> clazz= Class.forName("MyUnidbgScripts.Person"); // 通过类的完整名加载
Class<?> clazz2=ClassLoader.getSystemClassLoader().loadClass("MyUnidbgScripts.Person");// 通过classloader加载
// 非动态加载
Class<?> clazz3=Person.class;
Class<?> clazz4=new Person().getClass();
System.out.println("Load Class:");
System.out.println(clazz);
System.out.println(clazz2);
System.out.println(clazz3);
System.out.println(clazz4);
System.out.println();
 
//2. 从类对象获取类的各种信息
System.out.println("Class info:");
System.out.println(clazz.getName());       // 完整类名
System.out.println(clazz.getSimpleName()); // 类名
System.out.println(clazz.getSuperclass()); // 父类类对象
System.out.println(Arrays.toString(clazz.getInterfaces()));    //接口类对象数组
System.out.println();
```

输入如下：

```
Load Class:
class MyUnidbgScripts.Person
class MyUnidbgScripts.Person
class MyUnidbgScripts.Person
class MyUnidbgScripts.Person
 
Class info:
MyUnidbgScripts.Person
Person
class java.lang.Object
[interface java.lang.Runnable]
```



## 反射获取Constructor

- class.getConstructor(Class<?>... ParameterTypes) 获取class类指定参数类型的public构造方法
- class.getConstructors() 获取class类中的所有public权限的构造方法
- class.getDeclaredConstructor(Class<?>... ParameterTypes) 获取class类中的任意构造方法
- class.getDeclaredConstructors() 获取class类中的所有构造方法

```java
//3. 获取构造方法
// 获取无参构造方法(默认构造方法)
System.out.println("Get constructor:");
Constructor<?> constructor=clazz.getConstructor();
System.out.println(constructor);
System.out.println();
 
// 获取public构造方法
System.out.println("Get public constructors:");
Constructor<?>[] constructors=clazz.getConstructors();
System.out.println(Arrays.toString(constructors));
System.out.println();
 
// 获取所有构造方法
System.out.println("Get all constructors:");
constructors=clazz.getDeclaredConstructors();
System.out.println(Arrays.toString(constructors));
System.out.println("Print All Constructors:");
for(Constructor<?> cons:constructors){
    System.out.println("constructor: "+cons);
    System.out.println("\tname: "+cons.getName()+
            "\n\tModifiers: "+Modifier.toString(cons.getModifiers())+
            "\n\tParameterTypes: "+Arrays.toString(cons.getParameterTypes()));
}
System.out.println();
```

输入如下：

```
Get constructor:
public MyUnidbgScripts.Person()
 
Get public constructors:
[public MyUnidbgScripts.Person(java.lang.String,int), public MyUnidbgScripts.Person()]
 
Get all constructors:
[public MyUnidbgScripts.Person(java.lang.String,int), private MyUnidbgScripts.Person(java.lang.String), public MyUnidbgScripts.Person()]
Print All Constructors:
constructor: public MyUnidbgScripts.Person(java.lang.String,int)
    name: MyUnidbgScripts.Person
    Modifiers: public
    ParameterTypes: [class java.lang.String, int]
constructor: private MyUnidbgScripts.Person(java.lang.String)
    name: MyUnidbgScripts.Person
    Modifiers: private
    ParameterTypes: [class java.lang.String]
constructor: public MyUnidbgScripts.Person()
    name: MyUnidbgScripts.Person
    Modifiers: public
    ParameterTypes: []
```

## 反射获取Field

- class.getField(FieldName) 获取class类中的带public声明的FieldName变量
- class.getFields() 获取class类中的带public声明的所有变量
- class.getDeclaredField(FieldName) 获取class类中的FieldName变量
- class.getDeclaredFields() 获取class类中的所有变量

```java
//3. 获取属性
// 获取所有public属性
System.out.println("Get public fields:");
Field[] fields=clazz.getFields();
System.out.println(Arrays.toString(fields));
System.out.println();
 
// 获取所有属性
System.out.println("Get all fields:");
fields=clazz.getDeclaredFields();
System.out.println(Arrays.toString(fields));
System.out.println("Print all fields:");
for(Field field:fields){
    System.out.println("field: "+field);
    System.out.println("\ttype: "+field.getType()+
            "\n\tname: "+field.getName());
}
System.out.println();
 
System.out.println("Get specific field:");
// 获取public权限的指定属性
Field field=clazz.getField("name");
System.out.println(field);
// 获取任意权限的指定属性
field=clazz.getDeclaredField("age");
System.out.println(field);
```

输出如下

```
Get public fields:
[public java.lang.String MyUnidbgScripts.Person.name]
 
Get all fields:
[public java.lang.String MyUnidbgScripts.Person.name, private int MyUnidbgScripts.Person.age]
Print all fields:
field: public java.lang.String MyUnidbgScripts.Person.name
    type: class java.lang.String
    name: name
field: private int MyUnidbgScripts.Person.age
    type: int
    name: age
 
Get specific field:
public java.lang.String MyUnidbgScripts.Person.name
private int MyUnidbgScripts.Person.age
```

## 反射获取Method

- class.getMethod(MethodName,...ParameterTypes) 获取指定方法名和指定参数的public方法
- class.getMethods() 获取class类中所有public方法
- class.getDeclaredMethod(MethodName,...ParameterTypes) 获取class类中指定方法名和指定参数的任意方法
- class.getDeclaredMethods() 获取class类的所有方法

- class.getMethod(MethodName,...ParameterTypes) 获取指定方法名和指定参数的public方法
- class.getMethods() 获取class类中所有public方法
- class.getDeclaredMethod(MethodName,...ParameterTypes) 获取class类中指定方法名和指定参数的任意方法
- class.getDeclaredMethods() 获取class类的所有方法

```java
//4. 获取方法
System.out.println("Get public methods:");
Method[] methods=clazz.getMethods();   // 注意会获取所实现接口的public方法
System.out.println(Arrays.toString(methods));
System.out.println();
 
System.out.println("Get all methods:");
methods=clazz.getDeclaredMethods();    // 获取所有声明的方法
System.out.println(Arrays.toString(methods));
System.out.println();
 
System.out.println("Print all methods:");
for(Method method:methods){
    System.out.println("method: "+method);
    System.out.println("\tname: "+method.getName());
    System.out.println("\treturnType: "+method.getReturnType());
    System.out.println("\tparameterTypes: "+Arrays.toString(method.getParameterTypes()));
}
System.out.println();
 
// 获取public的指定方法
Method method=clazz.getMethod("introduce");
System.out.println(method);
// 获取任意权限的指定方法
method=clazz.getDeclaredMethod("privateMethod",String.class,int.class);
System.out.println(method);
System.out.println();
```

输出如下

```
Get public methods:
[public void MyUnidbgScripts.Person.run(), public void MyUnidbgScripts.Person.introduce(), public final void java.lang.Object.wait(long,int) throws java.lang.InterruptedException, public final void java.lang.Object.wait() throws java.lang.InterruptedException, public final native void java.lang.Object.wait(long) throws java.lang.InterruptedException, public boolean java.lang.Object.equals(java.lang.Object), public java.lang.String java.lang.Object.toString(), public native int java.lang.Object.hashCode(), public final native java.lang.Class java.lang.Object.getClass(), public final native void java.lang.Object.notify(), public final native void java.lang.Object.notifyAll()]
 
Get all methods:
[public void MyUnidbgScripts.Person.run(), public void MyUnidbgScripts.Person.introduce(), private void MyUnidbgScripts.Person.privateMethod(java.lang.String,int)]
 
Print all methods:
method: public void MyUnidbgScripts.Person.run()
    name: run
    returnType: void
    parameterTypes: []
method: public void MyUnidbgScripts.Person.introduce()
    name: introduce
    returnType: void
    parameterTypes: []
method: private void MyUnidbgScripts.Person.privateMethod(java.lang.String,int)
    name: privateMethod
    returnType: void
    parameterTypes: [class java.lang.String, int]
 
public void MyUnidbgScripts.Person.introduce()
private void MyUnidbgScripts.Person.privateMethod(java.lang.String,int)
```

## 反射创建对象

- 通过Class.newInstance() 调用无参构造方法创建实例 不能传递参数

- 通过Constructor.newInstance() 调用指定构造方法创建实例 可传递参数

```java
//5. 反射创建对象
System.out.println("Create instance by reflection:");
//5.1 Class.newInstance() 要求Class对象对应类有无参构造方法,执行无参构造方法创建实例
System.out.println("Create instance by Class.newInstance():");
Object obj=clazz.newInstance();
System.out.println(obj.toString());
System.out.println();
 
//5.2 Constructor.newInstance() 通过Class获取Constructor,再创建对象,可使用指定构造方法
System.out.println("Create instance by Constructor.newInstance():");
Constructor<?> cons=clazz.getConstructor();// 获取无参构造方法
obj=cons.newInstance();
System.out.println(obj.toString());
cons=clazz.getDeclaredConstructors()[0];// 获取有参构造方法
obj=cons.newInstance("张三",18);
System.out.println(obj.toString());
System.out.println();
```

输入如下：

```
Create instance by reflection:
Create instance by Class.newInstance():
MyUnidbgScripts.Person@30dae81
 
Create instance by Constructor.newInstance():
MyUnidbgScripts.Person@1b2c6ec2
MyUnidbgScripts.Person@4edde6e5
```

## 反射操作属性

- Class.getField(FieldName) 获取指定名称的public属性

- Class.getDeclaredField(FieldName) 获取指定名称的任意属性

- Field.get(Object obj) 获取指定实例的值

- Field.set(Object obj,Object value) 设置指定实例的值

- Field.setAccessible(true) 突破属性权限控制

```java
//6. 反射操作属性
 System.out.println("Access field by reflection:");
 Field nameField=clazz.getField("name");
 nameField.set(obj,"王五");    // 修改指定对象的指定属性
 Field ageField=clazz.getDeclaredField("age");
 ageField.setAccessible(true);// 突破权限控制
 ageField.set(obj,20);
 System.out.println(nameField.get(obj));// get方法获取字段值
 System.out.println(ageField.get(obj));
```

输出：

```
Access field by reflection:
王五
20
```

## 反射调用方法

- Class.getMethod(String name,Class<?>... parameterTypes) 获取指定名称和参数类型的public方法

- Class.getDeclaredMethod(String name,Class<?>... parameterTypes) 获取指定名称和参数类型的方法

- Method.setAccessible(true) 突破访问权限控制

- Method.invoke(Object obj,Object... args) 调用指定实例的方法,可传递参数

```java
//7. 反射调用方法
 System.out.println("Run method by reflection:");
 Method introduceMethod=clazz.getMethod("introduce");
 introduceMethod.invoke(obj); //person.introduce()
 Method privateMethod=clazz.getDeclaredMethod("privateMethod",String.class,int.class);// person.privateMethod("赵四",19)
 privateMethod.setAccessible(true);
 privateMethod.invoke(obj,"赵四",19);
```

输出：

```
Run method by reflection:
我是王五,年龄20
这是Person的私有方法,name=赵四,age=19
```

