============== SPRING SECURITY FILTERS  ======================
1. Trong toàn bộ Web/App Server nói chung sẽ sử dụng các Filter để đóng vai trò intercept các Request được gửi từ Client tới. Với mục tiêu tiền xử lý và chuyển thành các đối tượng Request mà Web server(Servlet container) có thể hiểu được.
2. Spring Security cũng sử dụng khái niệm này đối với inbuilt filters của nó. Các Filter này được thiết lập bên trong SecurityFilterChain như CSRF Filter, CORS Filter, Channel Processing Filter.... Các Filter này được cấu hình trong **_ProjectSecurityConfig_**
3. Các Filters phía trước sau khi thực hiện xong sẽ Forward HTTP object cho các Filters phía sau thực hiện logic riêng của nó.


=================== QUAN TRỌNG =========================
1. Ngay sau khi các Filters làm việc xong(Spring app và Spring Security) thì Request sẽ được chuyển sang cho DispatcherServlet, nó sẽ có nhiệm vụ Map các Endpoint với Các RestController/Controller tương ứng.

===================== CSRF Attack Protection in Stateless Server. ======================

Reference Documentation: _https://docs.spring.io/spring-security/reference/servlet/exploits/csrf.html#csrf-integration-javascript-spa_ 

1. Nếu làm việc với các hệ thống Stateless thông qua JWT Tokens thì việc bảo vệ hệ thống khởi CSRF attacks là điều cần thiết. Bởi vì, JWT tokens chỉ chịu trách nhiệm cho việc triển khai Stateless và Authen/author. Ngoài những vấn đề trên thì JWT tokens sẽ khá giống với SessionID vì nó cũng được lưu ở Cookies. Và vì việc lưu ở Cookies nó cũng sẽ có tiềm ẩn khả năng khiến hệ thống bị tấn công CSRF.
2. Để triển khai việc bảo vệ khỏi CSRF, trước hết chúng ta phải tạo ra các CSRF Tokens đi kèm với JWT Tokens. Các bước xử lý của CSRF Tokens + JWT Tokens khác giống với CSRF Tokens + JSessionID Token. Chúng ta sẽ phải lưu CSRF Tokens ở Cookies. Khi Client thực hiện một POST/PUT/PATCH/DELETE... method thì phải đính kèm CSRF Tokens cùng với Request.
3. Sử dụng CookieCsrfTokenRepository để thực hiện việc **_write cookie named XSRF-TOKEN_** và **_read it from HTTP request header named X-XSRF-TOKEN_** **_or the request parameter _csrf by default_**
4. **_Using CsrfTokenRequestAttributeHandler_**: 
   1. CsrfTokenRequestAttributeHandler giúp cho CsrfToken có sẵn dưới dạng một thuộc tính của HttpServletRequest là "_csrf".
   2. CsrfToken cũng có sẵn dưới dạng thuộc tính của HttpServletRequest CsrfToken.class.getName() => CsrfToken token = (CsrfToken) request.getAttribute(CsrfToken.class.getName());


===================== UsernamePasswordAuthenticationFilter. ======================
1. _Processes an authentication form submission_. Called AuthenticationProcessingFilter prior to Spring Security 3.0.
2. _Login forms must present two parameters to this filter: a username and password._ The default parameter names to use are contained in the static fields SPRING_SECURITY_FORM_USERNAME_KEY and SPRING_SECURITY_FORM_PASSWORD_KEY. The parameter names can also be changed by setting the usernameParameter and passwordParameter properties. 
3. This filter by default responds to the **_URL /login._**

===================== IMPLEMENTS SECURITY BY USING JWT TOKEN. ======================
1. Để triển khai thành công Security sử dụng JWT Token chúng ta cần:
   1. Tạo ra 2 Filters quan trọng là: JwtTokenGeneratorFilter(thực thi phía sau **_BasicAuthenticationFilter_**) và **_JwtTokenValidatorFilter_** thực hiện đối với các Role cần xác thực.
   2. Filter **_JwtTokenGeneratorFilter_** chỉ áp dụng trong trường hợp Client sử dụng Basic Authorization header. Bởi vì khi đó, BasicAuthentication mới thực thi và JwtToken... sẽ được gọi ngay sau đó.
   3. Đối với việc xác thực thông qua API /login. Thì chúng ta phải làm theo cách khác đối với tiêu chuẩn thông thường. Cho  phép permitAll() với /login. Sau đó tạo ra @Bean AuthenticationManager và authenticate thủ công Authentication object.
2. BasicAuthenticationFilter chịu trách nhiệm cho việc xử lý bất kỳ request nào có header là Authorization với authentication scheme là Basic và một base64e encode (username:password) theo sau. Đây là kiểu xác thực cổ điển nhất, nó yêu cầu username:password phải bắt buộc có trong Basic Authorization header.
3. **_BasicAuthenticationFilter_**:
   1. Processes a HTTP request's BASIC authorization headers, putting the result into the **_SecurityContextHolder_**.
   2. If authentication is successful, the resulting Authentication object will be placed into the SecurityContextHolder.
   3. If authentication fails and ignoreFailure is false (the default), an **_AuthenticationEntryPoint_** implementation is called (unless the ignoreFailure property is set to true). Usually this should be _**BasicAuthenticationEntryPoint**_, _which will prompt the user to authenticate again via BASIC authentication._
   4. In summary, this filter is responsible for processing any request that has a HTTP request header of _Authorization_ with an authentication scheme of _Basic_ and a _Base64-encoded username:password token_. For example, to authenticate user "Aladdin" with password "open sesame" the following header would be presented:
      _Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==

4. Chúng ta không thể sử dụng standard flow khi có endpoint POST /login bởi vì nếu dùng thì endpoint này sẽ phải dùng các Provider được định nghĩa sẵn của Manager trước đó và không thể tạo ra JWT Token được. Còn nếu suy nghĩ đến việc điều chỉnh hàm authenticate() của UsernamePwdAuthenticationProvider cũng là không thể bởi vì hàm này chỉ chấp nhận một tham số là Authenticate và cũng chỉ trả về một object là Authenticate.
5. Khi chúng ta generate 1 Cookie object thì hãy lưu ý tới hàm .path("endpoint"). Vì chúng ta phải định nghĩ domain nào mà chúng ta muốn sử dụng Cookie này. Ví dụ nếu path("/api/v1/admin") thì chắc chắn là Cookie này sẽ không xuất hiện trong "/api/v1/users".


=================== WRITE UNIT TESTING =========================
1. Khi thực hiện viết unit test với Controller layer. Nên nhớ phải thêm 2 Annotations là @SpringBootTest @AutoConfigureMockMvc. @AutoConfigureMockMvc có mục đích là tự động cấu hình cho MockMvc nên chúng ta không cần phải thực hiện cấu hình thủ công cho nó.
2. Mục đích của MockMvc là nó sẽ mô phỏng lại một HTTP request và sau đó gửi tới cho Server. Bên trong request này cũng sẽ có các phần như Header, Cookies....


=================== NÊN ĐẶT JWTTOKENVALIDATORFILTER Ở ĐÂU.======================
reference: https://stackoverflow.com/questions/59302026/spring-security-why-adding-the-jwt-filter-before-usernamepasswordauthenticatio