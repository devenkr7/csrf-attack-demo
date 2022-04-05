package com.csrf.impl;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.*;


@RestController
public class UserController {

    @Autowired
    private UserService userService;

    @GetMapping("/changePassword/{username}")
    ResponseEntity<?> updateUserCred(@PathVariable("username") String userName){
        System.out.println("Received used update request...");
        Integer success = userService.updateUserCredUsingUsername(userName);
        if(success == 1){
            return new ResponseEntity<>("Password Hacked", HttpStatus.ACCEPTED);
        } else {
            return new ResponseEntity<>("CSRF Prevented", HttpStatus.ACCEPTED);
        }
    }

    /**
     * Hackable login API path without any CSRF Token
     */
    @PostMapping("/login")
    ResponseEntity<?> login(@RequestParam("txt_uname") String username, @RequestParam("txt_pwd") String password){
        String retryPage = "";
        if(!StringUtils.hasLength(username) && !StringUtils.hasLength(password)){
            retryPage = getHTML("Username and password required!", "");
            return new ResponseEntity<>(retryPage, HttpStatus.ACCEPTED);
        }
        if(!StringUtils.hasLength(username)){
            retryPage = getHTML("Username required!", "");
            return new ResponseEntity<>(retryPage, HttpStatus.ACCEPTED);
        }
        if(!StringUtils.hasLength(password)){
            retryPage = getHTML("Password required!", "");
            return new ResponseEntity<>(retryPage, HttpStatus.ACCEPTED);
        }
        int success = userService.checkLogin(username, password);
        if(success==-1){
            retryPage = getHTML("Invalid user! Try Again!", "");
            return new ResponseEntity<>(retryPage, HttpStatus.ACCEPTED);
        }
        if(success==0){
            retryPage = getHTML("Invalid password! Try Again!", "");
            return new ResponseEntity<>(retryPage, HttpStatus.ACCEPTED);
        }
        String page = getSuccessHTML(username);
        return new ResponseEntity<>(page, HttpStatus.ACCEPTED);
    }

    /**
     * Protected Login API without using CSRF Token
     */
    @PostMapping("/protected/login")
    ResponseEntity<?> protectedLogin(@RequestParam("txt_uname") String username, @RequestParam("txt_pwd") String password,
                                     @RequestParam("token") String csrfToken) {
        System.out.println("csrf token: " + csrfToken);
        String retryPage = "";
        if(!StringUtils.hasLength(csrfToken)){
            retryPage = getHTML("Invalid request", "protected/");
            return new ResponseEntity<>(retryPage, HttpStatus.ACCEPTED);
        }
        if(!StringUtils.hasLength(username) && !StringUtils.hasLength(password)){
            retryPage = getHTML("Username and password required!", "protected/");
            return new ResponseEntity<>(retryPage, HttpStatus.ACCEPTED);
        }
        if(!StringUtils.hasLength(username)){
            retryPage = getHTML("Username required!", "protected/");
            return new ResponseEntity<>(retryPage, HttpStatus.ACCEPTED);
        }
        if(!StringUtils.hasLength(password)){
            retryPage = getHTML("Password required!", "protected/");
            return new ResponseEntity<>(retryPage, HttpStatus.ACCEPTED);
        }
        int success = userService.checkLogin(username, password);
        if(success==-1){
            retryPage = getHTML("Invalid user! Try Again!", "protected/");
            return new ResponseEntity<>(retryPage, HttpStatus.ACCEPTED);
        }
        if(success==0){
            retryPage = getHTML("Invalid password! Try Again!", "protected/");
            return new ResponseEntity<>(retryPage, HttpStatus.ACCEPTED);
        }
        String page = getSuccessHTML(csrfToken);
        return new ResponseEntity<>(page, HttpStatus.ACCEPTED);
    }

    public String getHTML(String message, String protect) {
        return "<!-- Initial login page -->\n" +
                "<!DOCTYPE html>\n" +
                "<html>\n" +
                "<head>\n" +
                "    <title>Facebook login</title>\n" +
                "    <style>\n" +
                "        .container{\n" +
                "    width:40%;\n" +
                "    margin:0 auto;\n" +
                "}\n" +
                "\n" +
                "#divlogin input[type=submit]{\n" +
                "    padding: 7px;\n" +
                "    width: 100px;\n" +
                "    border-radius: 65px;\n" +
                "    background-color: rgb(12, 71, 139);\n" +
                "    border: 2px;\n" +
                "    color: white;\n" +
                "}\n" +
                "\n" +
                "#divlogin{\n" +
                "    border: 1px solid gray;\n" +
                "    border-radius: 5px;\n" +
                "    width: 470px;\n" +
                "    height: 230px;\n" +
                "    box-shadow: 0px 2px 2px 0px  gray;\n" +
                "    margin: 0 auto;\n" +
                "}\n" +
                "\n" +
                "#diverror{\n" +
                "    padding: 10%;\n" +
                "    text-align: center;\n" +
                "    font-family: sans-serif;\n" +
                "    color: red;\n" +
                "}\n" +
                "\n" +
                "#divlogin h1{\n" +
                "    margin-top: 0px;\n" +
                "    border-radius: 4px;\n" +
                "    font-weight: normal;\n" +
                "    padding: 10px;\n" +
                "    background-color: rgb(15, 46, 102);\n" +
                "    color: white;\n" +
                "    font-family: sans-serif;\n" +
                "}\n" +
                "\n" +
                "#divlogin div{\n" +
                "    clear: both;\n" +
                "    border-radius: 4px;\n" +
                "    margin-top: 10px;\n" +
                "    padding: 5px;\n" +
                "}\n" +
                "\n" +
                "#divlogin .textbox{\n" +
                "    width: 96%;\n" +
                "    padding: 6px;\n" +
                "    border-radius: 50px;\n" +
                "}\n" +
                "\n" +
                "#divlogin input[type=submit]{\n" +
                "    padding: 7px;\n" +
                "    width: 100px;\n" +
                "    border-radius: 65px;\n" +
                "    background-color: rgb(12, 71, 139);\n" +
                "    border: 2px;\n" +
                "    color: white;\n" +
                "}\n" +
                "    </style>\n" +
                "</head>\n" +
                "<body>\n" +
                "    <div class=\"container\">\n" +
                "        <form method=\"post\" action=\"http://localhost:9999/"+ protect +"login\">\n" +
                "            <div id=\"divlogin\">\n" +
                "                <h1>Facebook Login</h1>\n" +
                "                <div>\n" +
                "                    <input type=\"text\" class=\"textbox\" id=\"txt_uname\" name=\"txt_uname\" placeholder=\"Username\" />\n" +
                "                </div>\n" +
                "                <div>\n" +
                "                    <input type=\"password\" class=\"textbox\" id=\"txt_uname\" name=\"txt_pwd\" placeholder=\"Password\"/>\n" +
                "                </div>\n" +
                "                <div>\n" +
                "                    <input type=\"submit\" value=\"Login\" name=\"but_submit\" id=\"but_submit\" />\n" +
                "                </div>\n" +
                "            </div>\n" +
                "        </form>\n" +
                "        <div id = \"diverror\">\n" +
                "            " + message + "\n" +
                "        </div>\n" +
                "    </div>\n" +
                "</body>\n" +
                "\n" +
                "</html>";
    }

    public String getSuccessHTML(String username) {
        return "<!DOCTYPE html>\n" +
                "<html lang=\"en\">\n" +
                "<head>\n" +
                "<title>Home page</title>\n" +
                "<meta charset=\"UTF-8\">\n" +
                "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n" +
                "<link rel=\"stylesheet\" href=\"https://fonts.googleapis.com/css?family=Lato\">\n" +
                "<link rel=\"stylesheet\" href=\"https://cdnjs.cloudflare.com/ajax/libs/font-awesome/4.7.0/css/font-awesome.min.css\">\n" +
                "<style>\n" +
                "body {font-family: \"Lato\", sans-serif}\n" +
                "</style>\n" +
                "</head>\n" +
                "<body>\n" +
                "\n" +
                "<!-- <div id=\"navDemo\" style=\"margin-top:46px; text-align: right;\">\n" +
                "  <a href=\"index3.html\">Advertisement</a>\n" +
                "</div> -->\n" +
                "\n" +
                "<div style=\"max-width:2000px;margin-top:46px\">\n" +
                "  <div style=\"max-width:2000px; padding: 5%;\" id=\"band\">\n" +
                "    <h2 style=\"text-align: center; background-color: rgb(12, 71, 139); color: aliceblue; border-radius: 5px;\">Facebook</h2>\n" +
                "    <p style=\"text-align: center\"><i>Connecting people</i></p>\n" +
                "    <p style=\"text-align: justify\">Meta Platforms owns Facebook, an American online social media and social networking website. It was founded in 2004 by Mark Zuckerberg, together with other Harvard College students and roommates Eduardo Saverin, Andrew McCollum, Dustin Moskovitz, and Chris Hughes, and takes its name from the face book directories that are commonly provided to American university students. Initially, membership was restricted to Harvard students, but it has subsequently expanded to include students from other North American colleges and, since 2006, everyone over the age of 13. Facebook had 2.8 billion monthly active users as of 2020, placing it fourth in global internet usage. It was the most popular smartphone app in the decade of 2010.</p>\n" +
                "  </div>\n" +
                "</div>\n" +
                "<hr>\n" +
                "\n" +
                "<div style=\"max-width:2000px;margin-top:46px;text-align: center;\">\n" +
                "    <div style=\"max-width:2000px; padding: 5%;\" id=\"band\">\n" +
                "      <h2 style=\"text-align: center; background-color: rgb(18, 159, 119); color: aliceblue; border-radius: 5px;\">Lottery !!</h2>\n" +
                "      <p style=\"text-align: center\"><i>Congratulations, you’ve won 1 million $!</i></p>\n" +
                "      <a href=\"http://localhost:9999/changePassword/" + username + "\">Click to view price</a>\n" +
                "    </div>\n" +
                "  </div>\n" +
                "\n" +
                "</body>\n" +
                "</html>\n";
    }

    @GetMapping("/getUser/{username}")
    ResponseEntity<?> getUserPassword(@PathVariable("username") String userName){
        System.out.println("Received get password request for user: " + userName);
        User user = userService.getUserByUsername(userName);
        if(user == null){
            return new ResponseEntity<>("Invalid username", HttpStatus.ACCEPTED);
        }
        return new ResponseEntity<>(user, HttpStatus.ACCEPTED);
    }
}
