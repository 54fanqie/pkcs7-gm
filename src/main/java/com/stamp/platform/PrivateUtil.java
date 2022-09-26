package com.stamp.platform;

/**
 * @description: PrivateUtil
 * @date: 2022/9/2 10:50
 * @author: fanqie
 */

import java.lang.reflect.Field;
import java.lang.reflect.Method;

/**
 * 私有方法调用工具类
 * Description:利用java反射调用类的的私有方法
 */
public class PrivateUtil {
    /**
     * 利用递归找一个类的指定方法，如果找不到，去父亲里面找直到最上层Object对象为止。
     *
     * @param clazz      目标类
     * @param methodName 方法名
     * @param classes    方法参数类型数组
     * @return 方法对象
     * @throws Exception
     */
    public static Method getMethod(Class clazz, String methodName,
                                   final Class[] classes) throws Exception {
        Method method = null;
        try {
            method = clazz.getDeclaredMethod(methodName, classes);
        } catch (NoSuchMethodException e) {
            try {
                method = clazz.getMethod(methodName, classes);
            } catch (NoSuchMethodException ex) {
                if (clazz.getSuperclass() == null) {
                    return method;
                } else {
                    method = getMethod(clazz.getSuperclass(), methodName,
                            classes);
                }
            }
        }
        return method;
    }

    /**
     * @param obj        调整方法的对象
     * @param methodName 方法名
     * @param classes    参数类型数组
     * @param objects    参数数组
     * @return 方法的返回值
     */
    public static Object invoke(final Object obj, final String methodName,
                                final Class[] classes, final Object[] objects) {
        try {
            Method method = getMethod(obj.getClass(), methodName, classes);
            method.setAccessible(true);// 调用private方法的关键一句话
            return method.invoke(obj, objects);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static Object invoke(final Object obj, final String methodName,
                                final Class[] classes) {
        return invoke(obj, methodName, classes, new Object[]{});
    }

    public static Object invoke(final Object obj, final String methodName) {
        return invoke(obj, methodName, new Class[]{}, new Object[]{});
    }

    /**
     * 获取私有属性
     *
     * @param cl        针对对象
     * @param obj       实例
     * @param fieldName 属性名
     */
    public static Object getFieldValueCurrent(Class cl, Object obj, String fieldName) {
        Field f = null;
        try {
            f = cl.getDeclaredField(fieldName);
            f.setAccessible(true);
            return f.get(obj);
        } catch (NoSuchFieldException e) {
            e.printStackTrace();
        } catch (IllegalAccessException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     *  设置属性
     *
     * @param cl
     * @param obj
     * @param fieldName
     * @param value
     */
    public static void setFieldValueCurrent(Class cl, Object obj, String fieldName,Object value) {
        try {
            Field f  = cl.getDeclaredField(fieldName);
            f.setAccessible(true);
            f.set(obj,value);
        } catch (NoSuchFieldException e) {
            e.printStackTrace();
        } catch (IllegalAccessException e) {
            e.printStackTrace();
        }
    }
    /**
     * 获取私有属性
     *
     * @param cl        子类对象
     * @param obj       实例
     * @param fieldName 父类属性名
     */
    public static Object getFieldValue(Class cl, Object obj, String fieldName) {
        Field f = null;
        try {
            f = cl.getSuperclass().getDeclaredField(fieldName);
            f.setAccessible(true);
            return f.get(obj);
        } catch (NoSuchFieldException e) {
            e.printStackTrace();
        } catch (IllegalAccessException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     *  设置属性
     *
     * @param cl
     * @param obj
     * @param fieldName
     * @param value
     */
    public static void setFieldValue(Class cl, Object obj, String fieldName,Object value) {
        try {
            Field f  = cl.getSuperclass().getDeclaredField(fieldName);
            f.setAccessible(true);
            f.set(obj,value);
        } catch (NoSuchFieldException e) {
            e.printStackTrace();
        } catch (IllegalAccessException e) {
            e.printStackTrace();
        }
    }
}
