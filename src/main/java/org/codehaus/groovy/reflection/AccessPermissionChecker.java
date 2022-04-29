/*
 *  Licensed to the Apache Software Foundation (ASF) under one
 *  or more contributor license agreements.  See the NOTICE file
 *  distributed with this work for additional information
 *  regarding copyright ownership.  The ASF licenses this file
 *  to you under the Apache License, Version 2.0 (the
 *  "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 */
package org.codehaus.groovy.reflection;

import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.lang.reflect.ReflectPermission;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.apache.groovy.util.SystemUtil;

import groovy.lang.GroovyObject;

@SuppressWarnings("removal") // TODO future Groovy versions should deprecate then remove this class
final class AccessPermissionChecker {

    private static final ReflectPermission REFLECT_PERMISSION = new ReflectPermission("suppressAccessChecks");
    private static final List<String> blacklist;

    static {
        String blacklistString = SystemUtil.getSystemPropertySafe("groovy.blacklist", null);
        if(blacklistString != null) {
            blacklist = Arrays.asList(blacklistString.split(","));
        } else {
            blacklist = new ArrayList<>();
        }
    }

    private AccessPermissionChecker() {
    }

    private static void checkAccessPermission(Class<?> declaringClass, final String name, final int modifiers, boolean isAccessible) {
        final SecurityManager securityManager = System.getSecurityManager();

        final boolean hasProtectedFlag = (modifiers & (Modifier.PROTECTED)) != 0;
        final boolean hasPublicFlag = (modifiers & (Modifier.PUBLIC)) != 0;

        final boolean accessGranted = (hasPublicFlag && classChainIsPublic(declaringClass)) ||
                GroovyObject.class.isAssignableFrom(declaringClass);

        if (securityManager != null && isAccessible) {
            if (hasProtectedFlag && declaringClass.equals(ClassLoader.class)) {
                securityManager.checkCreateClassLoader();
            } else if (isBlacklisted(name) || !accessGranted) {
                securityManager.checkPermission(REFLECT_PERMISSION);
            }
        }
    }

    private static boolean classChainIsPublic(Class<?> declaringClass) {
        Class<?> clazz = declaringClass;
        while(clazz != null) {
            final boolean hasPublicFlag = (clazz.getModifiers() & Modifier.PUBLIC) != 0;

            if(!clazz.isAnonymousClass() && !hasPublicFlag) {
                return false;
            }
            clazz = clazz.getDeclaringClass();
        }

        return true;
    }

    private static boolean isBlacklisted(String name) {
        return blacklist.stream().anyMatch(name::startsWith);
    }

    static void checkAccessPermission(Method method) {
        try {
            String qualifiedName = String.join(".", method.getDeclaringClass().getTypeName(),  method.getName());
            checkAccessPermission(method.getDeclaringClass(), qualifiedName, method.getModifiers(), method.isAccessible());
        } catch (java.security.AccessControlException e) {
            throw createCacheAccessControlExceptionOf(method, e);
        }
    }

    static void checkAccessPermission(Constructor constructor) {
        try {
            String qualifiedName = constructor.getDeclaringClass().getTypeName();
            checkAccessPermission(constructor.getDeclaringClass(), qualifiedName, constructor.getModifiers(), constructor.isAccessible());
        } catch (java.security.AccessControlException e) {
            throw createCacheAccessControlExceptionOf(constructor, e);
        }
    }

    private static CacheAccessControlException createCacheAccessControlExceptionOf(Method method, java.security.AccessControlException e) {
        return new CacheAccessControlException(
                "Groovy object can not access method " + method.getName()
                        + " cacheAccessControlExceptionOf class " + method.getDeclaringClass().getName()
                        + " with modifiers \"" + Modifier.toString(method.getModifiers()) + "\"", e);
    }

    private static CacheAccessControlException createCacheAccessControlExceptionOf(Constructor constructor, java.security.AccessControlException e) {
        return new CacheAccessControlException(
                "Groovy object can not access constructor " + constructor.getName()
                        + " cacheAccessControlExceptionOf class " + constructor.getDeclaringClass().getName()
                        + " with modifiers \"" + Modifier.toString(constructor.getModifiers()) + "\"", e);
    }

    static void checkAccessPermission(Field field) {
        try {
            String qualifiedName = String.join(".", field.getDeclaringClass().getTypeName(),  field.getName());
            checkAccessPermission(field.getDeclaringClass(), qualifiedName, field.getModifiers(), field.isAccessible());
        } catch (java.security.AccessControlException e) {
            throw createCacheAccessControlExceptionOf(field, e);
        }
    }

    private static CacheAccessControlException createCacheAccessControlExceptionOf(Field field, java.security.AccessControlException e) {
        return new CacheAccessControlException(
                "Groovy object can not access field " + field.getName()
                        + " cacheAccessControlExceptionOf class " + field.getDeclaringClass().getName()
                        + " with modifiers \"" + Modifier.toString(field.getModifiers()) + "\"", e);
    }

}
