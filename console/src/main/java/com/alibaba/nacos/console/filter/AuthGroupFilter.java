/*
 * Copyright 1999-2018 Alibaba Group Holding Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.alibaba.nacos.console.filter;

import com.alibaba.nacos.auth.AuthManager;
import com.alibaba.nacos.auth.annotation.Secured;
import com.alibaba.nacos.auth.common.AuthConfigs;
import com.alibaba.nacos.auth.exception.AccessException;
import com.alibaba.nacos.auth.model.Permission;
import com.alibaba.nacos.auth.model.User;
import com.alibaba.nacos.auth.parser.ResourceParser;
import com.alibaba.nacos.common.utils.ExceptionUtil;
import com.alibaba.nacos.config.server.auth.PermissionInfo;
import com.alibaba.nacos.console.security.nacos.roles.NacosRoleServiceImpl;
import com.alibaba.nacos.core.code.ControllerMethodsCache;
import com.alibaba.nacos.core.utils.Loggers;
import com.alibaba.nacos.core.utils.WebUtils;
import com.alibaba.nacos.sys.env.Constants;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.lang.reflect.Method;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

/**
 * group filter to handle authentication and authorization.
 *
 * @author kongxuan
 * @since 2.0
 */
public class AuthGroupFilter implements Filter {

    @Autowired
    private AuthConfigs authConfigs;

    @Autowired
    private NacosRoleServiceImpl nacosRoleService;

    @Autowired
    private ControllerMethodsCache methodsCache;

    @Autowired
    private AuthManager authManager;

    private Map<Class<? extends ResourceParser>, ResourceParser> parserInstance = new ConcurrentHashMap<>();

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {


        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse resp = (HttpServletResponse) response;
        ModifyParametersWrapper mParametersWrapper = new ModifyParametersWrapper(req);



        try {

            Method method = methodsCache.getMethod(req);
            if (method == null) {
                chain.doFilter(request, response);
                return;
            }

            if (method.isAnnotationPresent(Secured.class) ) {
                Secured secured = method.getAnnotation(Secured.class);
                String action = secured.action().toString();
                String resource = secured.resource();

                if(StringUtils.isBlank(req.getParameter("group"))){
                    String tenant=req.getParameter("tenant");
                    User user=authManager.login(req);
                    Set<PermissionInfo> sets=nacosRoleService.foundAllPermission(user.getUserName());
                    List<String> groups=sets.stream().filter(e-> e.getResource().startsWith(tenant+":")).map(e-> {
                        String r=e.getResource();
                        String items[]=r.split(":");
                        return items[1];
                    }).collect(Collectors.toList());
                    if(groups.size()>0){
                        mParametersWrapper.addParameter("group",groups);
                    }
                    System.out.println(groups.size());
                }


            }
            chain.doFilter(mParametersWrapper, response);
        } catch (IllegalArgumentException e) {
            resp.sendError(HttpServletResponse.SC_BAD_REQUEST, ExceptionUtil.getAllExceptionMsg(e));
            return;
        } catch (Exception e) {
            resp.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Server failed," + e.getMessage());
            return;
        }
    }

    private ResourceParser getResourceParser(Class<? extends ResourceParser> parseClass)
            throws IllegalAccessException, InstantiationException {
        ResourceParser parser = parserInstance.get(parseClass);
        if (parser == null) {
            parser = parseClass.newInstance();
            parserInstance.put(parseClass, parser);
        }
        return parser;
    }


    /**
     * 继承HttpServletRequestWrapper，创建装饰类，以达到修改HttpServletRequest参数的目的
     */
    private class ModifyParametersWrapper extends HttpServletRequestWrapper {
        private Map<String, String[]> parameterMap; // 所有参数的Map集合

        public ModifyParametersWrapper(HttpServletRequest request) {
            super(request);
            parameterMap = new HashMap(request.getParameterMap());
        }

        //重载一个构造方法
        public ModifyParametersWrapper(HttpServletRequest request, Map<String, Object> extendParams) {
            this(request);
            addAllParameters(extendParams);//这里将扩展参数写入参数表
        }

            // 重写几个HttpServletRequestWrapper中的方法
        /**
         * 获取所有参数名
         *
         * @return 返回所有参数名
         */
        @Override
        public Enumeration<String> getParameterNames() {
            Vector<String> vector = new Vector<String>(parameterMap.keySet());
            return vector.elements();
        }


        @Override
        public String getParameter(String name) {//重写getParameter，代表参数从当前类中的map获取
            String[] values = parameterMap.get(name);
            if (values == null || values.length == 0) {
                return null;
            }
            return values[0];
        }

        public String[] getParameterValues(String name) {//同上
            return parameterMap.get(name);
        }

        public void addAllParameters(Map<String, Object> otherParams) {//增加多个参数
            for (Map.Entry<String, Object> entry : otherParams.entrySet()) {
                addParameter(entry.getKey(), entry.getValue());
            }
        }

        public void addParameter(String name, Object value) {//增加参数
            if (value != null) {
                if (value instanceof ArrayList) {
                    String value1 = String.valueOf(value).substring(1, String.valueOf(value).length());
                    value = value1.substring(0, value1.length() - 1);
                    parameterMap.put(name, new String[]{(String) value});
                } else if (value instanceof String[]) {
                    parameterMap.put(name, (String[]) value);
                } else if (value instanceof String) {
                    parameterMap.put(name, new String[]{(String) value});
                } else {
                    parameterMap.put(name, new String[]{String.valueOf(value)});
                }
            }
        }


    }
}
