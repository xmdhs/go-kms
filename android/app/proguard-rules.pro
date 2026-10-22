# Project-specific ProGuard/R8 rules.

# LogPanelView 通过布局 XML 反射实例化，需要保留其构造函数。
-keep class com.xmdhs.gokms.LogPanelView {
    public <init>(...);
}
