---
title: "Objective-C底层原理"
date: 2025-05-21
layout: post
categories: 
- iOS,Objective-C
tags: 
- iOS,Objective-C
description: >
  这篇文章说说Objective-C的底层机制，主要是类的内存分布，如何支持一些语言特性，再说说进程启动的时候会有哪些的操作。
---

<!--more-->



这篇文章说说Objective-C的底层机制，主要是类的内存分布，如何支持一些语言特性，再说说进程启动的时候会有哪些的操作。

## OC底层原理

### OC类对象本质

oc本质：oc会被编译成C\C++代码，面向对象都是基于C\C++的struct

```shell
clang -rewrite-objc main.m -o main.cpp 
xcrun -sdk iphoneos clang -arch arm64 -rewrite-objc main.m -o main.cpp 
xcrun -sdk iphoneos clang -arch arm64 -rewrite-objc main.m -S //汇编
clang -rewrite-objc -fobjc-arc -fobjc-runtime=ios-13.0.0 -isysroot /Applicatons/Xcode.app/Contents/Developer/Platforms/iPhoneSimulator-platform/Developer/SDKs/iPhoneSimulator13.7.sdk main.m
```

```objective-c
@interface NSObject{
  Class isa;
}
@end
struct NSObject_IMPL{
  Class isa;
}
typedef struct objc_class *Class;

```

### 特殊方法

#### alloc init new方法

alloc:  开辟内存 16字节对齐

init : return (id)self 构造方法，工厂设计，提供继承重载初始化

new = alloc + init。new不会调用父类的init。

一些hack方法：

```
class_getInstanceSize(); //    查看类的内存大小
malloc_size(); //实际分配的内存大小。
```

#### load方法：

程序启动时就会调用，装载类信息：

`_objc_load_image`会调用call_load_methods()：先调用类的load然后再去调用分类的load。

#### initialize方法：

当类第一次接受到消息时会调用。会先调用父类的initialize。

在callInitialize中。



### OC运行时机制：

#### 类对象简介：

- instance对象（实例对象）：通过alloc出来的对象。
  - instance对象在内存中保存着成员变量。

- class对象（类对象）：
  - 通过实例对象获取Class的两种方法，
    - Class xxx = [test class];
    - Class xxx = object_getClass(test);
  - 保存的信息：
    - isa指针
    - 类的属性信息(@property)、类的对象方法信息(instance method)
    - 类的协议信息(protocol)、类的成员信息(ivar)

- meta-class对象（元类对象）：
  - 将Class作为参数传进object_getClass获取元类对象。
  - 保存的信息：
    - 类方法信息

**-开头方法的放在class中，+开头的放在meta-class中**





可以在编译出来后的ida中查看class和meta-class：

```c
__objc_data:00000001000080F0 ; Segment type: Regular
__objc_data:00000001000080F0 ; Segment permissions: Read/Write
__objc_data:00000001000080F0 __objc_data     segment qword public '' use64
__objc_data:00000001000080F0                 assume cs:__objc_data
__objc_data:00000001000080F0                 ;org 1000080F0h
__objc_data:00000001000080F0                 assume es:nothing, ss:nothing, ds:nothing, fs:nothing, gs:nothing
__objc_data:00000001000080F0                 public _OBJC_METACLASS_$_test
__objc_data:00000001000080F0 _OBJC_METACLASS_$_test __objc2_class <offset _OBJC_METACLASS_$_NSObject, \
__objc_data:00000001000080F0                                         ; DATA XREF: __objc_data:_OBJC_CLASS_$_test↓o
__objc_data:00000001000080F0                                offset _OBJC_METACLASS_$_NSObject, \
__objc_data:00000001000080F0                                offset __objc_empty_cache, 0, offset test_$metaData>
__objc_data:0000000100008118                 public _OBJC_CLASS_$_test
__objc_data:0000000100008118 _OBJC_CLASS_$_test __objc2_class <offset _OBJC_METACLASS_$_test, \
__objc_data:0000000100008118                                         ; DATA XREF: __objc_classlist:0000000100004060↑o
__objc_data:0000000100008118                                         ; __objc_classrefs:classRef_test↑o
__objc_data:0000000100008118                                offset _OBJC_CLASS_$_NSObject, \
__objc_data:0000000100008118                                offset __objc_empty_cache, 0, offset test_$classData>
__objc_data:0000000100008118 __objc_data     ends
```

关于它的内存结构后面会详细说明：



#### Category机制的工作流程

在 Objective-C 中，**Category**（分类）是一种在不修改原始类（`@interface/@implementation`）的源代码，也不需要子类化的情况下，向现有类添加方法（但**不能**添加实例变量）的机制。它的工作流程在运行时大致可用下面的 ASCII 图表示：

```
           ┌───────────────────────────────────┐
           │     编译期生成：Category 对象        │
           │   (名字: MyClass+Additions)        │
           │───────────────────────────────────│
           │ class_name: "MyClass"             │
           │ method_list:                      │
           │   + (void)catMethod1;             │
           │   - (NSString*)catMethod2;        │
           └───────────────────────────────────┘
                          │
      链接 & 加载时，把 Category 的方法表挂到目标类────┐
                          ▼                       │
┌──────────────────────────────┐        ┌────────────────────────────────┐
│       Runtime: MyClass       │        │ Runtime: MyClass+Additions     │
│ ┌──────────────────────────┐ │        │ ┌──────────────────────────┐   │
│ │  original_method_list    │ │        │ │ category_method_list     │   │
│ │  [m1, m2, ...]           │ │        │ │ [catMethod1, catMethod2] │   │
│ └──────────────────────────┘ │        │ └──────────────────────────┘   │
└──────────────────────────────┘        └────────────────────────────────┘
                          │
                          │ Runtime 合并（插入到最前面 —— 覆盖原有同名方法）
                          ▼
┌─────────────────────────────────────────────────┐
│             Runtime: MyClass (合并后)            │
│ ┌─────────────────────────────────────────────┐ │
│ │ final_method_list                           │ │
│ │ [catMethod1, catMethod2, m1, m2, ...]       │ │
│ └─────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────┘

```

#### 使用方法：

```objective-c
@interface MyClass (Additions)
- (void)catMethod1;
- (NSString*)catMethod2;
@end

@implementation MyClass (Additions)
- (void)catMethod1 { /* ... */ }
- (NSString*)catMethod2 { return @"hello"; }
@end

```

当程序加载到内存，Category 里的方法会被插入到目标类（`MyClass`）的 method list 前端；如果与原类存在同名方法，就会覆盖原有实现。

Category 只能增加方法，无法改变类实例的内存布局。若需要增加属性 backed by ivar，请改用 **Extension**（类扩展）或子类。

如果一个类有多个 Category，哪一个先插入、哪一个后插入并没有严格保证，所以不要在不同 Category 中互相覆盖同一个方法来制造“链式调用”——行为未定义。

#### 用途：

- 给系统类（如 `NSString`、`UIViewController`）添加方便调用的工具方法
- 按模块分文件组织同一类的庞大接口
- 声明私有方法（不过更推荐用类扩展）

#### isa:

```
+---------------+      +--------------------------------+      +--------------------+
|   instance    | ---->|             class              | ---->|     meta-class     |
+---------------+      +--------------------------------+      +--------------------+
| isa           |      | isa                            |      | isa                |
| 其他成员变量    |      | superclass                     |      | superclass         |
+---------------+      | 属性、对象方法、协议、成员变量       |      | 类方法              |
                       | ......                         |      | ......             |
                       +--------------------------------+      +--------------------+

```



- 当调用对象方法时，通过instance的isa找到class，最后找到对象方法的实现进行调用
- 当调用类方法时，通过class的isa找到meta-class，最后找到类方法的实现进行调用

使用调试器查看isa的内部结构

```c
(lldb) p (class_data_bits_t*)0x1000081e0
(class_data_bits_t *) 0x00000001000081e0
(lldb) p ((class_data_bits_t*)0x1000081e0)->data()
(class_rw_t *) 0x000060000207d000
  
(lldb) p ((class_rw_t *) 0x000060000207d000)->ro_or_rw_ext
(explicit_atomic<unsigned long>) {
  std::__1::atomic<unsigned long> = {
    Value = 4295000312
  }
}
(lldb) p/x 4295000312
(long) 0x00000001000080f8
  
(lldb) p ((class_rw_t *) 0x000060000207d000)->properties()
(const property_array_t) {
  list_array_tt<property_t, property_list_t, RawPtr> = {
    storage = (_value = 0)
  }
}

(lldb) p (((class_rw_t *) 0x000060000207d000)->methods())
(const method_array_t) {
  list_array_tt<method_t, method_list_t, method_list_t_authed_ptr> = {
    storage = (_value = 4295000136)
  }
}


  
```





#### objc_class的结构

结构体内容会随着版本不同而略有不同。（可能这就是苹果吧，说不支持就不支持）

```
+--------------------------------------------------------+
| struct objc_class {                                    |
|   Class isa;                                           |
|   Class superclass;                                    |
|   cache_t cache;           // 方法缓存                  |
|   class_data_bits_t bits;  // 用于获取具体的类信息        |
| };                                                     |
+--------------------------------------------------------+
                   │
                   │ bits & FAST_DATA_MASK
                   ▼
+--------------------------------------------------------+
| struct class_rw_t {                                    |
|   uint32_t flags;                                      |
|   uint32_t version;                                    |
|   const class_ro_t *ro;       ←─── 指向下方 class_ro    |
|   method_list_t *methods;     // 方法列表               |
|   property_list_t *properties; // 属性列表              |
|   const protocol_list_t *protocols; // 协议列表         |
|   Class firstSubclass;                                 |
|   Class nextSiblingClass;                              |
|   char *demangledName;                                 |
| };                                                     |
+--------------------------------------------------------+
                   │
                   │  ro 指针
                   ▼
+--------------------------------------------------------+
| struct class_ro_t {                                    |
|   uint32_t flags;                                      |
|   uint32_t instanceStart;                              |
|   uint32_t instanceSize;   // instance 对象占用的内存空间 |
| #ifdef __LP64__                                        |
|   uint32_t reserved;                                   |
| #endif                                                 |
|   const uint8_t *ivarLayout;                           |
|   const char *name;          // 类名                    |
|   method_list_t *baseMethodList;                       |
|   protocol_list_t *baseProtocols;                      |
|   const ivar_list_t *ivars; // 成员变量列表              |
|   const uint8_t *weakIvarLayout;                       |
|   property_list_t *baseProperties;                     |
| };                                                     |
+--------------------------------------------------------+

```



##### objc_class

```c
struct objc_class {
    Class isa;  // 指向元类（metaclass）
    Class superclass; // 父类
    cache_t cache;    // 方法缓存
    class_data_bits_t bits; // 核心数据 + 标志位
};
```

Objective-C 的类对象（`Class`）内部使用了一个联合体（union），将类的数据和一些额外的标志位信息合并存储在一个字段中。这种设计是为了节省内存并实现更高效的访问。`bits` 字段就是 `class_data_bits_t` 类型，它包含了以下两个重要部分：

1. **指向 `class_rw_t` 的指针**
   - `class_rw_t` 是“可读写”的类数据结构，包含方法列表、属性、协议等运行时动态修改的内容。
   - 你可以理解为它是类的实际内容。
2. **Tagged Pointer 风格的标志位（Bits）**
   - 利用指针地址的低位（通常是最后几位）来存储状态标志。
   - 因为内存对齐的原因，正常指针的低位通常为 0，所以可以安全地借用这些位作为标志。

通过调用类的方法（如 `class_getName`, `class_copyMethodList` 等），最终会调用到 runtime 内部的函数，从 `class_data_bits_t` 中提取出实际的 `class_rw_t *` 数据。大致逻辑如下：

```
class_rw_t* data() const {
    return (class_rw_t *)(bits & ~CLASS_DATA_MASK);
}
```

Objective-C 的类在运行时是可以动态扩展的（比如通过 Category 添加方法），这些动态添加的信息都保存在 `class_rw_t` 结构中。而 `class_data_bits_t` 正是连接到这个结构的桥梁。



##### cache_t

`cache_t` 是一个用于优化消息派发效率的数据结构。Objective-C 使用动态消息派发机制来调用对象的方法，这意味着每次发送消息（即调用方法）时，系统需要查找该方法的实现。为了加速这一过程，Objective-C 运行时使用了缓存机制，`cache_t` 就是这个缓存机制的核心数据结构。

大致结构：

```c
struct bucket_t {
    SEL _sel; // 方法选择器
    IMP _imp; // 方法实现
    // 可能还有其他字段，如下一个bucket的指针等
};

typedef struct cache_t {
    bucket_t *_buckets; // 指向桶数组的指针
    mask_t _mask; // 掩码，用于快速计算索引
    uint32_t _occupied; // 已占用的桶数
} cache_t;
```





##### class_rw_t

这个结构体在ida中看不到，在ida中通过bits直接看到的是class_ro_t

```c
struct class_rw_t {
    uint32_t flags;
    uint32_t witness;
    const class_ro_t *ro_or_rw_ext; // 指向只读部分的指针
    Class firstSubclass;
    Class nextSiblingClass;
};
```



`class_rw_t` 是一个非常重要的数据结构，它代表了一个类的“可读写”部分的数据。与之相对的是 `class_ro_t`（read-only），通常包含类定义时确定的信息。`class_rw_t` 包含了那些可以在运行时被修改的数据，比如方法列表、属性列表和协议列表等。

- **Ro**：指向 `class_ro_t` 结构体的指针，包含了只读部分的信息。



##### class_ro_t

```c
struct class_ro_t {
    uint32_t flags;
    uint32_t instanceStart;
    uint32_t instanceSize;
    uint32_t reserved;
    union {
        const uint8_t * ivarLayout;
        Class nonMetaclass;
    };
    const char *name;
    method_list_t *baseMethods;
    protocol_list_t *baseProtocols;
    ivar_list_t *ivars;
    const uint8_t *weakIvarLayout;
    property_list_t *baseProperties;
};
```

`class_ro_t` 在 Objective-C 中负责存储类的静态信息，提供了类的基本元数据以及编译时期确定的方法、属性和协议等信息。它与 `class_rw_t` 共同协作，支持了 Objective-C 的动态特性。

##### method_list_t

```c
typedef struct method_t {
    SEL name; // 方法名（选择器）
    const char *types; // 方法的类型编码
    IMP imp; // 方法实现
} method_t;

typedef struct method_list_t {
    uint32_t entsize; // 条目大小
    uint32_t count; // 方法数量
    first; // 第一个方法
    // 实际上，这里会跟随 'count' 个 method_t 结构体
} method_list_t;
```

一般情况下，`method_list_t` 结构体大致包含以下字段：

- **entsize**: 每个方法条目的大小，有助于遍历方法列表。
- **count**: 方法的数量。
- **first**: 方法数组的起始位置。每个元素是一个 `method_t` 结构体，代表一个单独的方法。

其中，`method_t` 结构体通常包括以下几个成员：

- **name**: 方法的选择器（selector），即方法的名字。
- **types**: 方法的类型编码字符串，描述了方法的参数和返回值类型。
- **imp**: 实现指针（Implementation Pointer），指向方法的实际实现代码。



##### property_list_t

属性提供了一种简洁的方式来声明类成员变量的访问器（getter 和 setter 方法），以及指定如何存储和访问这些变量。它简化了内存管理和线程安全等问题的处理。

`property_list_t` 是一个用于表示类属性列表的数据结构。它包含了类声明的所有属性的相关信息。通过 `property_list_t`，Objective-C 支持了属性的动态查询和操作，这是其强大反射机制的一部分。

```c
typedef struct property_t {
    const char *name; // 属性名称
    const char *attributes; // 属性的属性描述
} property_t;

typedef struct property_list_t {
    uint32_t entsize; // 条目大小
    uint32_t count; // 属性数量
    property_t list[]; // 属性数组
} property_list_t;
```

`property_list_t` 包含以下关键元素：

- **entsize**: 每个属性条目的大小，有助于遍历属性列表。
- **count**: 属性的数量。
- **list**: 属性数组的起始位置。每个元素是一个 `property_t` 结构体，代表一个单独的属性。

其中，`property_t` 结构体通常包括以下几个成员：

- **name**: 属性的名字。
- **attributes**: 属性的属性描述字符串，包含了如属性是原子性还是非原子性、是否为只读、关联的对象类型等信息。

利用 Objective-C 运行时函数如 `class_copyPropertyList` 可以获取某个类的所有属性列表，

使用示例：

```objective-c
@interface MyClass : NSObject
@property (nonatomic, retain) NSString *name;
@property (nonatomic, assign) NSInteger age;
@end

@implementation MyClass
@synthesize name = _name; // 自动生成实例变量_name及其存取方法
@end
```





##### protocol_list_t

协议定义了一组方法的列表，类可以采纳这些协议并实现其中的方法。这为 Objective-C 提供了类似其他语言中的接口（Interface）的功能。协议允许开发者定义一些通用的行为或能力，而不关心具体实现。

```c
typedef struct protocol_t {
    void * isa;  // NULL
    const char *protocol_name;
    const struct _protocol_list_t * protocol_list; // super protocols
    const struct method_list_t *instance_methods;
    const struct method_list_t *class_methods;
    const struct method_list_t *optionalInstanceMethods;
    const struct method_list_t *optionalClassMethods;
    const struct _prop_list_t * properties;
    const unsigned int size;  // sizeof(struct _protocol_t)
    const unsigned int flags;  // = 0
    const char ** extendedMethodTypes;
};

typedef struct protocol_list_t {
    uintptr_t count; // 协议数量
    protocol_t *list[]; // 协议数组
} protocol_list_t;
```

- **entsize**: 每个协议条目的大小，有助于遍历协议列表。
- **count**: 协议的数量。
- **list**: 协议数组的起始位置。每个元素是一个指向 `protocol_t` 的指针，代表一个单独的协议。

其中，`protocol_t` 结构体通常包括以下几个成员：

- **protocol_name**: 协议的名字。
- **protocols**: 该协议遵守的其他协议列表（即继承的协议）。
- **instanceMethods**: 实例方法列表。
- **classMethods**: 类方法列表。
- **optionalInstanceMethods**: 可选实例方法列表。
- **optionalClassMethods**: 可选类方法列表。
- **instanceProperties**: 实例属性列表。

使用示例：

```objective-c
@protocol MyProtocol <NSObject>
- (void)requiredMethod;
@optional
- (void)optionalMethod;
@end

@interface MyClass : NSObject <MyProtocol>
@end

@implementation MyClass
- (void)requiredMethod {
    NSLog(@"Required method implemented.");
}
// optionalMethod 可以不实现
@end
```



属性与协议结合使用：

协议和属性经常一起使用，特别是在设计框架或库时。例如，你可以定义一个协议来规定某些属性的存在，这样任何遵循该协议的类都必须实现这些属性。

```objective-c
@protocol UserProtocol <NSObject>
@property (nonatomic, copy) NSString *username;
@property (nonatomic, assign) NSUInteger userID;
@end

@interface User : NSObject <UserProtocol>
@end

@implementation User
@synthesize username = _username;
@synthesize userID = _userID;
@end
```





##### ivar_list_t

```c
typedef struct ivar_t {
    int32_t *offset;   //
    const char *name;  // 实例变量名称
    const char *type;  // 实例变量类型的编码字符串
    // alignment is sometimes -1; use alignment() instead
    uint32_t alignment_raw;
    uint32_t size;
} ivar_t;

typedef struct ivar_list_t {
    uint32_t entsize; // 条目大小
    uint32_t count; // 实例变量数量
    ivar_t first; // 第一个实例变量
    // 实际上，这里会跟随 'count' 个 ivar_t 结构体
} ivar_list_t;
```

- **entsize**: 每个实例变量条目的大小，有助于遍历实例变量列表。
- **count**: 实例变量的数量。
- **list**: 实例变量数组的起始位置。每个元素是一个 `ivar_t` 结构体，代表一个单独的实例变量。

其中，`ivar_t` 结构体通常包括以下几个成员：

- **name**: 实例变量的名字。
- **type**: 实例变量的类型编码字符串，描述了实例变量的数据类型。
- **offset**: 实例变量在对象内存布局中的偏移量，用于快速访问实例变量。
- **alignment**: 对齐要求，指定了实例变量在内存中的对齐方式。
- **size**: 实例变量占用的字节数。



#### cache



可以查看objc_runtime源码中的category_t的底层结构：里面有实例方法，类方法，协议，属性

```objective-c
struct category_t {
    const char *name;
    classref_t cls;
    WrappedPtr<method_list_t, method_list_t::Ptrauth> instanceMethods;
    WrappedPtr<method_list_t, method_list_t::Ptrauth> classMethods;
    struct protocol_list_t *protocols;
    struct property_list_t *instanceProperties;
    // Fields below this point are not always present on disk.
    struct property_list_t *_classProperties;

    method_list_t *methodsForMeta(bool isMeta) const {
        if (isMeta) return classMethods;
        else return instanceMethods;
    }

    property_list_t *propertiesForMeta(bool isMeta, struct header_info *hi) const;
    
    protocol_list_t *protocolsForMeta(bool isMeta) const {
        if (isMeta) return nullptr;
        else return protocols;
    }
};
```

`_read_images`:这个函数中有具体的操作。

#### 加载分类方法：

dyld会调用objc_init

​    _objc_init：运行时初始化调用

​        map_images

​            _read_images

​                remethodizeClass

#### 处理分类方法：

attachLists：

​    array()->lists：类对象原来的方法列表

​    addLists：所有分类的方法列表

​    将原来的方法列表往回move，然后把分类方法列表添加到前面，所以严格说法是不是覆盖，只是优先级比较高：

```objective-c
- (void)printMethodNamesOfClass:(Class)cls
{
    unsigned int count;
    // 获得方法数组
    Method *methodList = class_copyMethodList(cls, &count);
    
    // 存储方法名
    NSMutableString *methodNames = [NSMutableString string];
    
    // 遍历所有的方法
    for (int i = 0; i < count; i++) {
        // 获得方法
        Method method = methodList[i];
        // 获得方法名
        NSString *methodName = NSStringFromSelector(method_getName(method));
        // 拼接方法名
        [methodNames appendString:methodName];
        [methodNames appendString:@", "];
    }
    
    // 释放
    free(methodList);
    
    // 打印方法名
    NSLog(@"%@ - %@", cls, methodNames);
}
```



###  KVO key-value observing 键值监听

可以监听某个对象属性值的改变

使用：调用addObserver方法，options参数使用：

NSKeyValueObservingOptions options = NSKeyValueObservingOptionNew | NSKeyValueObservingOptionOld;



本质：如果你的使用了addObserver那么这个isa就变了。指向NSKVONotify_xxx。所以他会劫持set函数调用，新的set里面调用_NSSetIntValueAndNotify函数。所以如果直接修改变量是触发不了回调的，只有通过setter和KVC机制的修改才能让它触发回调。新的isa中有setXXX:, class, dealloc, _isKVOA,这么几个类方法

_NSSetIntValueAndNotify内部实现：

- 调用[self willChangeVallueForKey]
- 调用原来的setter实现
- 调用[self didChangeValueForKey]
  - 调用observer的observeValueForKeyPathofObject:change:context



### KVC Key-Value Coding 键值编码，可以通过一个key来访问某个属性

`- (void)setValue:(id)value forKeyPath:(NSString *)keyPath`

`- (void)setValue:(id)value forKey:(NSString *)key`

`- (id)valueforKeyPath:(NSString *)keyPath`

`- (id)valueforKey:(NSString *)key`

原理：

赋值过程：setValue:forkey: -> setKey，_setKey 没找到方法查看 accessInstanceVariablesDirectly方法返回值询问是否允许访问成员变量，不允许会抛异常，允许使用：`_key _isKey `顺序查找成员变量，找到了直接赋值。 

取值过程：set变get



### dylb启动加载动态库：

#### 调试dyld的方法：

1. 可以通过替换dyld的方式，将dyld替换成自己编译的。但是这种方法有风险，而且还得要关闭一些安全选项。

2. 通过dyld提供的环境变量来控制dyld在运⾏过程中输出有⽤信息。

```shell
1. DYLD_PRINT_APIS：打印dyld内部⼏乎所有发⽣的调⽤；
2. DYLD_PRINT_LIBRARIES：打印在应⽤程序启动期间正在加载的所有动态库；
3. DYLD_PRINT_WARNINGS：打印dyld运⾏过程中的辅助信息；
4. DYLD_*_PATH：显示dyld搜索动态库的⽬录顺序；
5. DYLD_PRINT_ENV：显示dyld初始化的环境变量；
6. DYLD_PRINT_SEGMENTS：打印当前程序的segment信息；
7. DYLD_PRINT_STATISTICS：打印pre-main time；
8. DYLD_PRINT_INITIALIZERS：显示都有initialiser。
```



#### 启动流程：

1. 执⾏⾃身初始化配置加载环境；LC_DYLD_INFO_ONLY
2. 加载当前程序链接的所有动态库到指定的内存中；LC_LOAD_DYLIB
3. 搜索所有的动态库，绑定需要在调⽤程序之前⽤的符号（⾮懒加载符号）；LC_DYSYMTAB
4. 在indirect symbol table中将需要绑定的导⼊符号真实地址替换；LC_DYSYMTAB
5. 向程序提供在Runtime时使⽤dyld的接⼝函数（存在libdyld.dylib中，由LC_LOAD_DYLIB提供）；
6. 配置Runtime，执⾏所有动态库/image中使⽤的全局构造函数；
7. dyld调⽤程序⼊⼝函数，开始执⾏程序。LC_MAIN



#### 源码分析

在这里下载对应版本的源码：https://opensource.apple.com/releases/

这是旧版的启动流程：

- __dyld_start()
  - dyldInitialzation.cpp`dyldbootstrap::start()
    - dyld2.cpp`dyld::_main()
      - instantiateFromLoadedImage()
        - ImageLoaderMachO.cpp`ImageLoaderMachO::instantiateMainExecutable()
          - runInitializers()
            - processInitializers()
              - ImageLoader::recursiveInitialization()递归实例化
                - doInitialization():
                  - doImageInit()
                - context.notifySingle()即notifySingle()
                  - (*sNotifyObjcInit)() 由_dyld_objc_notify_register()第二个参数指定。而这个函数由objc的objc_init()调用

这是新版的：

- __dyld_start() -----> jmp start() （在dyldMain.cpp中）

  - prepare() 主要操作都在这里。

    - JustInTimeLoader::loadDependents()（JustInTimeLoader.cpp）

      - MachOFile::forEachDependentDylib()（MachOFile.cpp）
        - MachOFile::forEachLoadCommand()（）
          - invocation function for block in dyld3::MachOFile::forEachDependentDylib(void (char const*, bool, bool, bool, unsigned int, unsigned int, bool&) block_pointer) const ()之前的第二个回调函数。
            - invocation function for block in dyld4::JustInTimeLoader::loadDependents(Diagnostics&, dyld4::RuntimeState&, dyld4::Loader::LoadOptions const&) ()
              - dyld4::JustInTimeLoader::matchesPath(char const*) const ()
                - dyld3::MachOFile::installName() const ()
                  - dyld3::MachOFile::getDylibInstallName(char const**, unsigned int*, unsigned int*) const ()
                    - dyld3::MachOFile::forEachLoadCommand(Diagnostics&, void (load_command const*, bool&) block_pointer) const () 递归处理依赖的dylib库

    - dyld4::APIs::runAllInitializersForMain() () 这是注册调用load方法的回调。

      - dyld4::JustInTimeLoader::runInitializers(dyld4::RuntimeState&) const ()

        - dyld4::Loader::findAndRunAllInitializers(dyld4::RuntimeState&) const ()

          - dyld3::MachOAnalyzer::forEachInitializer(Diagnostics&, dyld3::MachOAnalyzer::VMAddrConverter const&, void (unsigned int) block_pointer, void const*) const ()

            - dyld3::MachOFile::forEachSection(void (dyld3::MachOFile::SectionInfo const&, bool, bool&) block_pointer) const ()

              - dyld3::MachOFile::forEachLoadCommand(Diagnostics&, void (load_command const*, bool&) block_pointer) const ()

                - invocation function for block in dyld3::MachOFile::forEachSection(void (dyld3::MachOFile::SectionInfo const&, bool, bool&) block_pointer) const ()

                  - invocation function for block in dyld3::MachOAnalyzer::forEachInitializer(Diagnostics&, dyld3::MachOAnalyzer::VMAddrConverter const&, void (unsigned int) block_pointer, void const*) const ()

                    -  invocation function for block in dyld4::Loader::findAndRunAllInitializers(dyld4::RuntimeState&) const::$_0::operator()() const ()

                      - libSystem.B.dylib`libSystem_initializer()

                        - libdispatch.dylib`libdispatch_init()

                          - libdispatch.dylib`_os_object_init()

                            - libobjc.A.dylib`_objc_init()

                              - _dyld_objc_register_callbacks():

                                - ```cpp
                                      _dyld_objc_callbacks_v2 callbacks = {
                                          2, // version
                                          &map_images,
                                          &load_images,
                                          unmap_image,
                                          _objc_patch_root_of_class
                                      };
                                      _dyld_objc_register_callbacks((_dyld_objc_callbacks*)&callbacks);
                                  //调用load，这与下面的调试的堆栈信息匹配。
                                  ```

                          

        - runInitializersBottomUpPlusUpwardLinks()这里开始时调用全局构造函数的地方，在MachO的文件格式中会再添加一个section节，叫__init_offsets，这里保存着constructor函数的起始地址。

load:

```cpp
#0	0x0000000100003a80 in +[test load] at /Users/dh/Downloads/objc-runtime-6e3b46df961a4c889ae325cf67cd92186674fbd2/debug-objc/main.m:27
#1	0x0000000100b84856 in call_class_loads() at /Users/dh/Downloads/objc-runtime-6e3b46df961a4c889ae325cf67cd92186674fbd2/runtime/objc-loadmethod.mm:204
#2	0x0000000100b6998d in call_load_methods at /Users/dh/Downloads/objc-runtime-6e3b46df961a4c889ae325cf67cd92186674fbd2/runtime/objc-loadmethod.mm:353
#3	0x0000000100b69801 in load_images at /Users/dh/Downloads/objc-runtime-6e3b46df961a4c889ae325cf67cd92186674fbd2/runtime/objc-runtime-new.mm:3605
#4	0x00007ff8170f3dc3 in dyld4::RuntimeState::notifyObjCInit(dyld4::Loader const*) ()
#5	0x00007ff8170fdee6 in dyld4::Loader::runInitializersBottomUp(dyld4::RuntimeState&, dyld3::Array<dyld4::Loader const*>&) const ()
#6	0x00007ff817101040 in dyld4::Loader::runInitializersBottomUpPlusUpwardLinks(dyld4::RuntimeState&) const::$_1::operator()() const ()
#7	0x00007ff8170fdf87 in dyld4::Loader::runInitializersBottomUpPlusUpwardLinks(dyld4::RuntimeState&) const ()
#8	0x00007ff81711f96d in dyld4::APIs::runAllInitializersForMain() ()
#9	0x00007ff8170e9241 in dyld4::prepare(dyld4::APIs&, dyld3::MachOAnalyzer const*) ()
#10	0x00007ff8170e831f in start ()

```



全局构造函数的constructor调用过程：

```cpp
#1	0x00007ff817100fca in invocation function for block in dyld4::Loader::findAndRunAllInitializers(dyld4::RuntimeState&) const::$_0::operator()() const ()
#2	0x00007ff81714271f in invocation function for block in dyld3::MachOAnalyzer::forEachInitializer(Diagnostics&, dyld3::MachOAnalyzer::VMAddrConverter const&, void (unsigned int) block_pointer, void const*) const ()
#3	0x00007ff817136913 in invocation function for block in dyld3::MachOFile::forEachSection(void (dyld3::MachOFile::SectionInfo const&, bool, bool&) block_pointer) const ()
#4	0x00007ff8170e407f in dyld3::MachOFile::forEachLoadCommand(Diagnostics&, void (load_command const*, bool&) block_pointer) const ()
#5	0x00007ff817135adc in dyld3::MachOFile::forEachSection(void (dyld3::MachOFile::SectionInfo const&, bool, bool&) block_pointer) const ()
#6	0x00007ff81714230a in dyld3::MachOAnalyzer::forEachInitializer(Diagnostics&, dyld3::MachOAnalyzer::VMAddrConverter const&, void (unsigned int) block_pointer, void const*) const ()
#7	0x00007ff8170fdcfc in dyld4::Loader::findAndRunAllInitializers(dyld4::RuntimeState&) const ()
#8	0x00007ff8171035cb in dyld4::JustInTimeLoader::runInitializers(dyld4::RuntimeState&) const ()
#9	0x00007ff8170fdef1 in dyld4::Loader::runInitializersBottomUp(dyld4::RuntimeState&, dyld3::Array<dyld4::Loader const*>&) const ()
#10	0x00007ff817101040 in dyld4::Loader::runInitializersBottomUpPlusUpwardLinks(dyld4::RuntimeState&) const::$_1::operator()() const ()
#11	0x00007ff8170fdf87 in dyld4::Loader::runInitializersBottomUpPlusUpwardLinks(dyld4::RuntimeState&) const ()
#12	0x00007ff81711f96d in dyld4::APIs::runAllInitializersForMain() ()
#13	0x00007ff8170e9241 in dyld4::prepare(dyld4::APIs&, dyld3::MachOAnalyzer const*) ()
#14	0x00007ff8170e831f in start ()

```

dyld4::prepare()函数会把main函数的返回地址return出来，然后start()直接调用。

```cpp
appMain = prepare(*state, dyldMA);

int result = appMain(state->config.process.argc, state->config.process.argv, state->config.process.envp, state->config.process.apple);

state->libSystemHelpers->exit(result);

```







