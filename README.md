# mobile-backend-platform Auth Module

Mobile Backend platform AuthModule 입니다.


    //////////////////////////////////////////////
    // USER REST API
    //////////////////////////////////////////////

    routeMatcher.get("/:key"){ req:HttpServerRequest =>{
      val urlParams = req.params
      req.response().end( urlParams("key").head)
    }}

    //Signing Up
    routeMatcher.post("/:version/users"){req:HttpServerRequest=>{
      /*
      curl -X POST \
        -H "X-Parse-Application-Id: HLhHyHljLIW4JDNhbWqg6Pkb0TL6tQYfNef2C2l4" \
        -H "X-Parse-REST-API-Key: Ymum9f8End4TNFom6H2dj2GDUTq41xJIJLotHT0L" \
       -H "Content-Type: application/json" \
       -d '{"username":"cooldude6","password":"p_n7!-e8","phone":"415-392-0202"}' \
        https://api.parse.com/1/users

        Status: 201 Created
        Location: https://api.parse.com/1/users/g7y9tkhB7O

        {
          "createdAt": "2011-11-07T20:58:34.448Z",
          "objectId": "g7y9tkhB7O",
          "sessionToken": "pnktnjyb996sj4p156gjtp4im"
        }
       */

      req.dataHandler{data : Buffer => {
        val sendJson = new JsonObject("""{"type":"signup","document":"""+data.toString()+"""}""")
        eventbus.send("ssky.auth",sendJson){msg:Message[JsonObject]=>{
          req.response().putHeader("Content-Type","application/json")
          req.response().putHeader("Location",config_ssky.getString("url") + "1/users/" + msg.body.getString("objectId"))
          req.response().end(msg.body.toString)
        }}
      }}

    }}

    //Logging In
    ////username and password as URL-encoded parameters:
    routeMatcher.get("/:version/login"){req:HttpServerRequest=>{
      /*
      curl -X GET \
      -H "X-Parse-Application-Id: HLhHyHljLIW4JDNhbWqg6Pkb0TL6tQYfNef2C2l4" \
      -H "X-Parse-REST-API-Key: Ymum9f8End4TNFom6H2dj2GDUTq41xJIJLotHT0L" \
      -G \
      --data-urlencode 'username=cooldude6' \
      --data-urlencode 'password=p_n7!-e8' \
      http://localhost:8080/1/login

      {
      "username": "cooldude6",
      "phone": "415-392-0202",
      "createdAt": "2011-11-07T20:58:34.448Z",
      "updatedAt": "2011-11-07T20:58:34.448Z",
      "objectId": "g7y9tkhB7O",
      "sessionToken": "pnktnjyb996sj4p156gjtp4im"
      }
      */

      val urlParams = req.params
      val userData = new JsonObject
      userData.putString("username",urlParams("username").head)
      userData.putString("password",urlParams("password").head)

      val sendJson = new JsonObject("""{"type":"login"}""")
      sendJson.putObject("document",userData)

      eventbus.send("ssky.auth",sendJson){msg:Message[JsonObject]=>{
        req.response().end(msg.body.toString)
      }}




    }}

    //Requesting A Password Reset
    routeMatcher.post("/:version/requestPasswordReset"){req:HttpServerRequest=>{
     /*
        curl -X POST \
        -H "X-Parse-Application-Id: HLhHyHljLIW4JDNhbWqg6Pkb0TL6tQYfNef2C2l4" \
        -H "X-Parse-REST-API-Key: Ymum9f8End4TNFom6H2dj2GDUTq41xJIJLotHT0L" \
        -H "Content-Type: application/json" \
        -d '{"email":"coolguy@iloveapps.com"}' \
        https://api.parse.com/1/requestPasswordReset
      */





    }}

    //Retrieving Users
    routeMatcher.get("/:version/users/:id"){req:HttpServerRequest=>{
    /*
        curl -X GET \
      -H "X-Parse-Application-Id: HLhHyHljLIW4JDNhbWqg6Pkb0TL6tQYfNef2C2l4" \
      -H "X-Parse-REST-API-Key: Ymum9f8End4TNFom6H2dj2GDUTq41xJIJLotHT0L" \
      https://api.parse.com/1/users/g7y9tkhB7O

        {
          "username": "cooldude6",
          "phone": "415-392-0202",
          "createdAt": "2011-11-07T20:58:34.448Z",
          "updatedAt": "2011-11-07T20:58:34.448Z",
          "objectId": "g7y9tkhB7O"
        }
     */
      val urlParams = req.params
      val userData = new JsonObject
      userData.putString("objectId",urlParams("id").head)

      val sendJson = new JsonObject("""{"type":"retrieve"}""")
      sendJson.putObject("document",userData)

      eventbus.send("ssky.auth",sendJson){msg:Message[JsonObject]=>{
        req.response().end(msg.body.toString)
      }}

    }}

    //Updating Users
    routeMatcher.put("/:version/users/:id"){req:HttpServerRequest=>{
     /*
        curl -X PUT \
        -H "X-Parse-Application-Id: HLhHyHljLIW4JDNhbWqg6Pkb0TL6tQYfNef2C2l4" \
        -H "X-Parse-REST-API-Key: Ymum9f8End4TNFom6H2dj2GDUTq41xJIJLotHT0L" \
        -H "X-Parse-Session-Token: pnktnjyb996sj4p156gjtp4im" \
        -H "Content-Type: application/json" \
        -d '{"phone":"415-369-6201"}' \
        https://api.parse.com/1/users/g7y9tkhB7O
        http://localhost:8080/1/users/g7y9tkhB7O

        {
           "updatedAt": "2011-11-07T21:25:10.623Z"
         }
      */

      val urlParams = req.params
      val headersData = req.headers

      req.dataHandler{data : Buffer => {
        val sendJson = new JsonObject("""{"type":"update","document":"""+data.toString()+"""}""")
        sendJson.getObject("document").putString("objectId",urlParams("id").head)
        sendJson.getObject("document").putString("sessionToken",headersData("X-Parse-Session-Token").head)

        eventbus.send("ssky.auth",sendJson){msg:Message[JsonObject]=>{
          req.response().end(msg.body.toString)
        }}

      }}



    }}

    //Querying
    routeMatcher.get("/:version/users"){req:HttpServerRequest=>{
    /*
      curl -X GET \
      -H "X-Parse-Application-Id: HLhHyHljLIW4JDNhbWqg6Pkb0TL6tQYfNef2C2l4" \
      -H "X-Parse-REST-API-Key: Ymum9f8End4TNFom6H2dj2GDUTq41xJIJLotHT0L" \
      https://api.parse.com/1/users

      {
        "results": [
          {
            "username": "bigglesworth",
            "phone": "650-253-0000",
            "createdAt": "2011-11-07T20:58:06.445Z",
            "updatedAt": "2011-11-07T20:58:06.445Z",
            "objectId": "3KmCvT7Zsb"
          },
          {
            "username": "cooldude6",
            "phone": "415-369-6201",
            "createdAt": "2011-11-07T20:58:34.448Z",
            "updatedAt": "2011-11-07T21:25:10.623Z",
            "objectId": "g7y9tkhB7O"
          }
        ]
      }
     */

      val sendJson = new JsonObject("""{"type":"query"}""")
      //sendJson.putObject("document",userData)

      eventbus.send("ssky.auth",sendJson){msg:Message[JsonObject]=>{
        req.response().end(msg.body.toString)
      }}



    }}

    //회원탈퇴
    routeMatcher.delete("/:version/users/:id"){req:HttpServerRequest=>{
    /*
        curl -X DELETE \
        -H "X-Parse-Application-Id: HLhHyHljLIW4JDNhbWqg6Pkb0TL6tQYfNef2C2l4" \
        -H "X-Parse-REST-API-Key: Ymum9f8End4TNFom6H2dj2GDUTq41xJIJLotHT0L" \
        -H "X-Parse-Session-Token: pnktnjyb996sj4p156gjtp4im" \
        https://api.parse.com/1/users/g7y9tkhB7O
     */
      val urlParams = req.params
      val headersData = req.headers

      val userData = new JsonObject
      userData.putString("objectId",urlParams("id").head)
      userData.putString("sessionToken",headersData("X-Parse-Session-Token").head)

      val sendJson = new JsonObject("""{"type":"delete"}""")
      sendJson.putObject("document",userData)
      eventbus.send("ssky.auth",sendJson){msg:Message[JsonObject]=>{
        req.response().end(msg.body.toString)
      }}


    }}


    vertx.createHttpServer.requestHandler(routeMatcher).listen(8080)