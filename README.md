# wisedu-login
金智教务登录模拟（for NBU）可用于通过https://uis.nbu.edu.cn进行统一登录验证的页面，如宁波大学网上办事大厅，宁波大学图书馆等

### 今日校园登录验证API构造分析

*This version is only written for NBU, but can adjust for other wisedu system*


#### NBU登录验证地址（loginUrl）

--------
```html
https://uis.nbu.edu.cn/authserver/login?service=http%3A%2F%2Fehall.nbu.edu.cn%2Flogin%3Fservice%3Dhttps%3A%2F%2Fehall.nbu.edu.cn%2Fnew%2Findex.html
```


#### 登录表单源码

--------
```html
<!-- 该代码片段截取自 loginUrl -->
<form id="casLoginForm" class="fm-v clearfix amp-login-form" role="form" action="/authserver/login?service=http%3A%2F%2Fehall.nbu.edu.cn%2Flogin%3Fservice%3Dhttps%3A%2F%2Fehall.nbu.edu.cn%2Fnew%2Findex.html" method="post">
    <p>
        <i class="auth_icon auth_icon_user"></i>
        <input id="username" name="username" placeholder="用户名/别名/已绑定手机/邮箱" class="auth_input" type="text" value="">
        <span id="usernameError" style="display:none;" class="auth_error">请输入用户名/别名/已绑定手机/邮箱</span>
    </p>

    <p>
        <i class="auth_icon auth_icon_pwd"></i>
        <input id="password" placeholder="密码" class="auth_input" type="password" value="" autocomplete="off">
        <input id="passwordEncrypt" name="password" style="display:none;" type="text" value="">
        <span id="passwordError" style="display:none;" class="auth_error">请输入密码</span>
    </p>
    <button type="submit" class="auth_login_btn_dl full_width" onclick="javascript:return submitcheck();">登录网上办事服务大厅</button>

    <input type="hidden" name="lt" value="LT-978424-JvFCPUP5vbWKYAgcZEcexSK5fsjzkn1616172880425-kztk-cas">
    <input type="hidden" name="dllt" value="userNamePasswordLogin">
    <input type="hidden" name="execution" value="e9s1">
    <input type="hidden" name="_eventId" value="submit">
    <input type="hidden" name="rmShown" value="1">
    <input type="hidden" id="pwdDefaultEncryptSalt" value="tvGnh2wajQkEqRcd">
</form>
```



#### 登录表单分析

--------
登录表单类型为`cas`，通过`form id`检索`casLoginForm`获取表单。

用户名为`username`，密码为`password`。

注意：密码需要加盐提交，盐的值从`form`中的`input.pwdDefaultEncryptSalt`的`value`获取，可知为`tvGnh2wajQkEqRcd`，初步测试，该盐值为固定字符串。

盐值使用提示：经过分析，`password`的`value`是经过`AES-128-CBC-PKCS5PADDING`加密后才进行提交的，其中盐值为加密的`key`



#### 构造程序分析

------

1. 由于认证页面为`https`，因此在构造程序的时候需要忽略证书错误后，才能去获取登录接口。
2. 解析页面，构造请求参数（param）
3. 构造请求头（header）
4. 验证是否需要验证码（https://uis.nbu.edu.cn/authserver/needCaptcha.html?username=）（注意：本项目验证码模块未完成）
5. 直接模拟登录，发送post请求，获取cookies。
   1. 这里有个坑，发送post请求后，response为一个`302`。
   2. 查看response的headers，若验证成功会返回3个set-cookie，失败会返回2个set-cookie（jsessionid和SF_cookie_6）
   3. 若密码错误应该会返回一个`200`，然后在`<form id="casLoginFrom" ...></form>`这个表单中，有个类似`<span id="msg>密码错误</span>"`的标签。
   4. 验证成功的情况下，跟随（`set-cookie`）一次`302`(`location`为`http`的`url`)后会遇到一次`301`，直接`location`到`https`的该`url`。
   5. 跟随一次`301`后还会响应一个`302`，该`302`带有`set-cookie`，拼接该`set-cookie`后继续跟随。该过程有多次`302`/`301`重定向，每次`302`会进行`set-cookie`，`301`会重定向至`https`的`url`。
   6. 持续这一过程后，若响应状态发生改变，则登录理论上成功。（我遇到过的情况，若来回`302/301`的时候的`method`为`POST`，则最后会返回`405`，即最后请求页面时，需要`GET`方式，不过此时`cookie`已经是完整的了；若一直是`GET`方式进行来回`302/301`，最后会直接获取到最终的需求页面，`response`为`200`）
