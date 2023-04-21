package ru.grobikon.oauth2.backend.controller;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;
import ru.grobikon.oauth2.backend.utils.CookieUtils;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/bff") // базовый URI
public class BFFController {

    // можно также использовать WebClient вместо RestTemplate, если нужны асинхронные запросы
    private static final RestTemplate restTemplate = new RestTemplate(); // для выполнения веб запросов на KeyCloak

    public static final String IDTOKEN_COOKIE_KEY = "IT";
    public static final String REFRESHTOKEN_COOKIE_KEY = "RT";
    public static final String ACCESSTOKEN_COOKIE_KEY = "AT";
    @Value("${keycloak.secret}")
    private String clientSecret;

    @Value("${resourceserver.url}")
    private String resourceServerURL;

    @Value("${keycloak.url}")
    private String keyCloakURI;


    @Value("${client.url}")
    private String clientURL;

    @Value("${keycloak.clientid}")
    private String clientId;

    @Value("${keycloak.granttype.code}")
    private String grantTypeCode;

    @Value("${keycloak.granttype.refresh}")
    private String grantTypeRefresh;

    private final CookieUtils cookieUtils; // класс-утилита для работы с куками

    @Autowired
    public BFFController(CookieUtils cookieUtils) {
        this.cookieUtils = cookieUtils;
    }


    // просто перенаправляет запрос в Resource Server и добавляет в него access token
    @GetMapping("/data")
    public ResponseEntity<String> data(@CookieValue("AT") String accessToken) {

        // обязательно нужно добавить заголовок авторизации с access token
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(accessToken); // слово Bearer будет добавлено автоматически

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(headers);

        ResponseEntity<String> response = restTemplate.exchange(resourceServerURL+ "/user/data", HttpMethod.GET, request, String.class);

        return response;
    }


    // получение новых токенов на основе старого RefreshToken
    @GetMapping("/newaccesstoken")
    public ResponseEntity<String> newAccessToken(@CookieValue("RT") String oldRefreshToken) {

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        // параметры запроса
        MultiValueMap<String, String> mapForm = new LinkedMultiValueMap<>();
        mapForm.add("grant_type", grantTypeRefresh);
        mapForm.add("client_id", clientId);
        mapForm.add("client_secret", clientSecret);
        mapForm.add("refresh_token", oldRefreshToken);

        // собираем запрос для выполнения
        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(mapForm, headers);

        // выполняем запрос (можно применять разные методы, не только exchange)
        ResponseEntity<String> response = restTemplate.exchange(keyCloakURI + "/token", HttpMethod.POST, request, String.class);

        try {

            // создаем куки для ответа в браузер
            HttpHeaders responseHeaders = createCookies(response);

            // отправляем клиенту ответ со всеми куками (которые запишутся в браузер автоматически)
            // значения куков с новыми токенами перезапишутся в браузер
            return ResponseEntity.ok().headers(responseHeaders).build();

        } catch (JsonProcessingException e) {
            e.printStackTrace();

        }

        // если ранее где-то возникла ошибка, то код переместится сюда, поэтому возвращаем статус с ошибкой
        return ResponseEntity.badRequest().build();
    }


    // удаление сессий пользователя внутри KeyCloak и также зануление всех куков
    @GetMapping("/logout")
    public ResponseEntity<String> logout(@CookieValue("IT") String idToken) {

        // 1. закрыть сессии в KeyCloak для данного пользователя
        // 2. занулить куки в браузере

        // чтобы корректно выполнить GET запрос с параметрами - применяем класс UriComponentsBuilder
        String urlTemplate = UriComponentsBuilder.fromHttpUrl(keyCloakURI + "/logout")
                .queryParam("post_logout_redirect_uri", "{post_logout_redirect_uri}")
                .queryParam("id_token_hint", "{id_token_hint}")
                .queryParam("client_id", "{client_id}")
                .encode()
                .toUriString();

        // конкретные значения, которые будут подставлены в параметры GET запроса
        Map<String, String> params = new HashMap<>();
        params.put("post_logout_redirect_uri", clientURL); // может быть любым, т.к. frontend получает ответ от BFF, а не напрямую от Auth Server
        params.put("id_token_hint", idToken); // idToken указывает Auth Server, для кого мы хотим "выйти"
        params.put("client_id", clientId);

        // выполняем запрос
        ResponseEntity<String> response = restTemplate.getForEntity(
                urlTemplate, // шаблон GET запроса
                String.class, // нам ничего не возвращается в ответе, только статус, поэтому можно указать String
                params // какие значения будут подставлены в шаблон GET запроса
        );


        // если KeyCloak вернул 200-ОК, значит сессии пользователя успешно закрыты и можно обнулять куки
        if (response.getStatusCode() == HttpStatus.OK) {

            // занулить значения и сроки годности всех куков (тогда браузер их удалит автоматически)
            HttpHeaders responseHeaders = clearCookies();

            // отправляем клиенту ответ с куками, которые автоматически применятся к браузеру
            return ResponseEntity.ok().headers(responseHeaders).build();
        }

        return ResponseEntity.badRequest().build();

    }


    // получение access token от лица клиента
    // но сами токены сохраняться в браузере не будут, а только будут передаваться в куках
    // таким образом к ним не будет доступа из кода браузера (защита от XSS атак)
    @PostMapping("/token")
    public ResponseEntity<String> token(@RequestBody String code) {// получаем auth code, чтобы обменять его на токены

        // 1. обменять auth code на токены
        // 2. сохранить токены в защищенные куки


        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        // параметры запроса
        MultiValueMap<String, String> mapForm = new LinkedMultiValueMap<>();
        mapForm.add("grant_type", grantTypeCode);
        mapForm.add("client_id", clientId);
        mapForm.add("client_secret", clientSecret);
        mapForm.add("code", code);

        // В случае работы клиента через BFF - этот redirect_uri может быть любым, т.к. мы не открываем окно вручную, а значит не будет автоматического перехода в redirect_uri
        // Клиент получает ответ в объекте ResponseEntity
        // НО! Значение все равно передавать нужно, без этого grant type не сработает и будет ошибка.
        // Значение обязательно должно быть с адресом и портом клиента, например https://localhost:8080  иначе будет ошибка Incorrect redirect_uri, потому что изначально запрос на авторизацию выполнялся именно с адреса клиента
        mapForm.add("redirect_uri", clientURL);

        // добавляем в запрос заголовки и параметры
        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(mapForm, headers);

        // выполняем запрос
        ResponseEntity<String> response = restTemplate.exchange(keyCloakURI + "/token", HttpMethod.POST, request, String.class);
        // мы получаем JSON в виде текста


        try {

            // считать данные из JSON и записать в куки
            HttpHeaders responseHeaders = createCookies(response);

            // отправляем клиенту данные пользователя (и jwt-кук в заголовке Set-Cookie)
            return ResponseEntity.ok().headers(responseHeaders).build();


        } catch (JsonProcessingException e) {
            e.printStackTrace();

        }

        // если ранее где-то возникла ошибка, то код переместится сюда, поэтому возвращаем статус с ошибкой
        return ResponseEntity.badRequest().build();

    }

    // создание куков для response
    private HttpHeaders createCookies(ResponseEntity<String> response) throws JsonProcessingException {

        // парсер JSON
        ObjectMapper mapper = new ObjectMapper();

        // сначала нужно получить корневой элемент JSON
        JsonNode root = mapper.readTree(response.getBody());

        // получаем значения токенов из корневого элемента JSON
        String accessToken = root.get("access_token").asText();
        String idToken = root.get("id_token").asText();
        String refreshToken = root.get("refresh_token").asText();

        // Сроки действия для токенов берем также из JSON
        // Куки станут неактивные в то же время, как выйдет срок действия токенов в KeyCloak
        int accessTokenDuration = root.get("expires_in").asInt();
        int refreshTokenDuration = root.get("refresh_expires_in").asInt();

        // создаем куки, которые браузер будет отправлять автоматически на BFF при каждом запросе
        HttpCookie accessTokenCookie = cookieUtils.createCookie(ACCESSTOKEN_COOKIE_KEY, accessToken, accessTokenDuration);
        HttpCookie refreshTokenCookie = cookieUtils.createCookie(REFRESHTOKEN_COOKIE_KEY, refreshToken, refreshTokenDuration);
        HttpCookie idTokenCookie = cookieUtils.createCookie(IDTOKEN_COOKIE_KEY, idToken, accessTokenDuration); // задаем такой же срок, что и AT

        // чтобы браузер применил куки к бразуеру - указываем их в заголовке Set-Cookie в response
        HttpHeaders responseHeaders = new HttpHeaders();
        responseHeaders.add(HttpHeaders.SET_COOKIE, accessTokenCookie.toString());
        responseHeaders.add(HttpHeaders.SET_COOKIE, refreshTokenCookie.toString());
        responseHeaders.add(HttpHeaders.SET_COOKIE, idTokenCookie.toString());

        return responseHeaders;
    }


    // зануляет все куки, чтобы браузер их удалил у себя
    private HttpHeaders clearCookies() {
        // зануляем куки, которые отправляем обратно клиенту в response, тогда браузер автоматически удалит их
        HttpCookie accessTokenCookie = cookieUtils.deleteCookie(ACCESSTOKEN_COOKIE_KEY);
        HttpCookie refreshTokenCookie = cookieUtils.deleteCookie(REFRESHTOKEN_COOKIE_KEY);
        HttpCookie idTokenCookie = cookieUtils.deleteCookie(IDTOKEN_COOKIE_KEY);

        // чтобы браузер применил куки к бразуеру - указываем их в заголовке Set-Cookie в response
        HttpHeaders responseHeaders = new HttpHeaders();
        responseHeaders.add(HttpHeaders.SET_COOKIE, accessTokenCookie.toString());
        responseHeaders.add(HttpHeaders.SET_COOKIE, refreshTokenCookie.toString());
        responseHeaders.add(HttpHeaders.SET_COOKIE, idTokenCookie.toString());
        return responseHeaders;
    }


}

