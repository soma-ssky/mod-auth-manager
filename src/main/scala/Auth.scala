
import org.vertx.java.core.AsyncResult
import org.vertx.java.core.buffer.Buffer
import org.vertx.scala.platform.Verticle
import org.vertx.scala.core.Vertx
import org.vertx.scala.core.eventbus._
import org.vertx.scala.core.http._
import org.vertx.scala.core.json._

import java.util.Date                     // ISODate
import java.text.SimpleDateFormat         // ISODate

import java.security.SecureRandom;        // Session
import java.math.BigInteger;              // Session

class Auth extends Verticle
{

  //////////////////////////////////////////////
  // User Module
  //////////////////////////////////////////////
  val dateFormat = new SimpleDateFormat("yyyy/MM/dd'T'HH:mm:ss.SSS'Z'")
  val random = new SecureRandom()

  def checkExist(msg:Message[JsonObject]):Boolean = {
    msg.body.getString("status").equals("ok") && (msg.body.getObject("result") != null)
  }

  //회원가입
  def users_signup(msg:Message[JsonObject]){

    val resultData = new JsonObject()
    val jsonData = new JsonObject("""{"action":"save","collection":"User"}""")

    //회원의 기본적인 데이터 입력
    msg.body.getObject("document").putString("createdAt",dateFormat.format(new Date))
    msg.body.getObject("document").putString("updatedAt",dateFormat.format(new Date))
    msg.body.getObject("document").putString("sessionToken",new BigInteger(130, random).toString(25))
    msg.body.getObject("document").putString("bcryptPassword",BCrypt.hashpw(msg.body.getObject("document").getString("password"),BCrypt.gensalt() ))

    msg.body.getObject("document").removeField("password")
    msg.body.getObject("document").removeField("_id")

    jsonData.putObject("document",msg.body.getObject("document"))
    vertx.eventBus.send("ssky.mongo",jsonData){mongoMsg:Message[JsonObject]=>{
      if(checkExist(mongoMsg)){
        resultData.putString("objectId",mongoMsg.body.getString("_id"))
        resultData.putString("createdAt",msg.body.getObject("document").getString("createdAt"))
        resultData.putString("sessionToken",msg.body.getObject("document").getString("sessionToken"))
        msg.reply(resultData)
      } else { // 회원정보가 이미 존재할때
        resultData.putString("code","202")
        resultData.putString("error","username "+msg.body.getObject("document").getString("username")+" already taken")
        msg.reply(resultData)
      }

    }}

  }

  //로그인
  def users_login(msg:Message[JsonObject]){

    val resultData = new JsonObject()
    val jsonData = new JsonObject("""{"action":"findone","collection":"User"}""")
    jsonData.putObject("matcher",new JsonObject("""{"username":""""+msg.body.getObject("document").getString("username")+""""}"""))

    vertx.eventBus.send("ssky.mongo",jsonData){mongoMsg:Message[JsonObject]=>{
      if(checkExist(mongoMsg)) {

        if(BCrypt.checkpw(msg.body.getObject("document").getString("password"),mongoMsg.body.getObject("result").getString("bcryptPassword"))==true){
          //회원의 개인정보 제거 후 출력
          mongoMsg.body.getObject("result").putString("objectId",mongoMsg.body.getObject("result").getString("_id"))
          mongoMsg.body.getObject("result").removeField("_id")
          mongoMsg.body.getObject("result").removeField("bcryptPassword")
          msg.reply(mongoMsg.body.getObject("result"))
        } else { // 회원의 비밀번호가 틀렸을 때
          resultData.putString("code","101")
          resultData.putString("error","invalid login parameters")
          msg.reply(resultData)
        }
      } else { // 회원 데이터베이스가 존재하지 않을때
        resultData.putString("code","101")
        resultData.putString("error","invalid login parameters")
        msg.reply(resultData)
      }
    }}

  }

  // 이메일 전송부분쪽 해결 필요
  // 이메일 검증 부분은 생략
  def users_verifyingEmail(msg:Message[JsonObject]){


  }

  //아이디 비밀번호 찾기
  def users_resetPassword(msg:Message[JsonObject]){

  }

  //사용자 정보 로드
  def users_retrieve(msg:Message[JsonObject]){

    val resultData = new JsonObject()
    val jsonData = new JsonObject("""{"action":"findone","collection":"User"}""")
    jsonData.putObject("matcher",new JsonObject("""{"_id":""""+msg.body.getObject("document").getString("objectId")+""""}"""))

    vertx.eventBus.send("ssky.mongo",jsonData){mongoMsg:Message[JsonObject]=>{
      if(checkExist(mongoMsg)) {

        mongoMsg.body.getObject("result").putString("objectId",mongoMsg.body.getObject("result").getString("_id"))
        mongoMsg.body.getObject("result").removeField("_id")
        mongoMsg.body.getObject("result").removeField("bcryptPassword")
        msg.reply(mongoMsg.body.getObject("result"))

      } else { // 회원 데이터베이스가 존재하지 않을때
        resultData.putString("code","101")
        resultData.putString("error","object not found for get")
        msg.reply(resultData)
      }
    }}

  }

  //회원정보 수정
  def users_update(msg:Message[JsonObject]){

    val resultData = new JsonObject()
    val jsonData = new JsonObject("""{"action":"findone","collection":"User"}""")
    println(msg.body.getObject("document").getString("username"))
    jsonData.putObject("matcher",new JsonObject("""{"username":""""+msg.body.getObject("document").getString("username")+""""}"""))

    vertx.eventBus.send("ssky.mongo",jsonData){mongoMsg:Message[JsonObject]=>{
      if(checkExist(mongoMsg)) {
        if(msg.body.getObject("document").getString("sessionToken") == mongoMsg.body.getObject("result").getString("sessionToken")) {

          msg.body.getObject("document").putString("updatedAt",dateFormat.format(new Date))

          var ChangePasswd:Boolean = false
          if(BCrypt.checkpw(msg.body.getObject("document").getString("password"),mongoMsg.body.getObject("result").getString("bcryptPassword"))==true){
            ChangePasswd = true
            msg.body.getObject("document").putString("sessionToken",new BigInteger(130, random).toString(25))
            msg.body.getObject("document").putString("bcryptPassword",BCrypt.hashpw(msg.body.getObject("document").getString("password"),BCrypt.gensalt() ))
            msg.body.getObject("document").removeField("password")
          }

          val jsonUpdateData = new JsonObject("""{"action":"update","collection":"User","criteria":{"_id",""""+msg.body.getObject("document").getString("objectId")+
            """"},"$set":{""""+msg.body.getObject("document")+""""}, "upsert" : "true", "multi" : "false" }""")

          vertx.eventBus.send("ssky.mongo",jsonUpdateData){mongoMsg:Message[JsonObject]=>{

            resultData.putString("updatedAt",msg.body.getObject("document").getString("updatedAt"))
            //비밀번호가 변경되면 세션도 다시 지정해줌.
            if(ChangePasswd) resultData.putString("sessionToken",msg.body.getObject("document").getString("sessionToken"))
            msg.reply(resultData)

          }}

        } else { // 회원의 비밀번호가 틀렸을 때
          resultData.putString("code","101")
          resultData.putString("error","invalid login parameters")
          msg.reply(resultData)
        }
      } else { // 회원 데이터베이스가 존재하지 않을때
        resultData.putString("code","101")
        resultData.putString("error","object not found for update")
        msg.reply(resultData)
      }
    }}

  }

  //회원정보쿼리
  def users_query(msg:Message[JsonObject]){

    val resultData = new JsonObject()
    val jsonData = new JsonObject("""{"action":"find","collection":"User"}""")
    println(msg.body.getObject("document").getString("username"))
    jsonData.putObject("matcher",new JsonObject("""{"username":""""+msg.body.getObject("document").getString("username")+""""}"""))

    vertx.eventBus.send("ssky.mongo",jsonData){mongoMsg:Message[JsonObject]=>{
      if(checkExist(mongoMsg)) {

        if(BCrypt.checkpw(msg.body.getObject("document").getString("password"),mongoMsg.body.getObject("result").getString("bcryptPassword"))==true){
          //회원의 개인정보 제거 후 출력
          mongoMsg.body.getObject("result").putString("objectId",mongoMsg.body.getObject("result").getString("_id"))
          mongoMsg.body.getObject("result").removeField("_id")
          mongoMsg.body.getObject("result").removeField("bcryptPassword")
          msg.reply(mongoMsg.body.getObject("result"))
        } else { // 회원의 비밀번호가 틀렸을 때
          resultData.putString("code","101")
          resultData.putString("error","invalid login parameters")
          msg.reply(resultData)
        }
      } else { // 회원 데이터베이스가 존재하지 않을때
        resultData.putString("code","101")
        resultData.putString("error","invalid login parameters")
        msg.reply(resultData)
      }
    }}

  }

  //회원 탈퇴
  def users_delete(msg:Message[JsonObject]){

    val resultData = new JsonObject()
    val jsonData = new JsonObject("""{"action":"findone","collection":"User"}""")
    println(msg.body.getObject("document").getString("username"))
    jsonData.putObject("matcher",new JsonObject("""{"username":""""+msg.body.getObject("document").getString("username")+""""}"""))

    vertx.eventBus.send("ssky.mongo",jsonData){mongoMsg:Message[JsonObject]=>{
      if(checkExist(mongoMsg)) {

        if(BCrypt.checkpw(msg.body.getObject("document").getString("password"),mongoMsg.body.getObject("result").getString("bcryptPassword"))==true){
          //회원의 개인정보 제거 후 출력
          mongoMsg.body.getObject("result").putString("objectId",mongoMsg.body.getObject("result").getString("_id"))
          mongoMsg.body.getObject("result").removeField("_id")
          mongoMsg.body.getObject("result").removeField("bcryptPassword")
          msg.reply(mongoMsg.body.getObject("result"))
        } else { // 회원의 비밀번호가 틀렸을 때
          resultData.putString("code","101")
          resultData.putString("error","invalid login parameters")
          msg.reply(resultData)
        }
      } else { // 회원 데이터베이스가 존재하지 않을때
        resultData.putString("code","101")
        resultData.putString("error","invalid login parameters")
        msg.reply(resultData)
      }
    }}


  }

  //SNS 연동
  def users_link(msg:Message[JsonObject]){


  }

  //Module Test
  def users_ping(msg:Message[JsonObject]){
    val pingReply = new JsonObject()
    pingReply.putString("type:","pong")
    pingReply.putString("time:",dateFormat.format(new Date))
    msg.reply(pingReply)
  }

  // Auth Event Handler
  def authHandle(msg:Message[JsonObject]){
    val event = msg.body.getString("type")

    event match{
      case "signup" => users_signup(msg)
      case "login" => users_login(msg)
      case "verifyingEmail" => users_verifyingEmail(msg)
      case "resetPassword" => users_resetPassword(msg)
      case "retrieve" => users_retrieve(msg)
      case "update" => users_update(msg)
      case "query" => users_query(msg)
      case "delete" => users_delete(msg)
      case "link" => users_link(msg)
      case "ping" => users_ping(msg)
    }
  }


  override def start()
  {

    val eventbus = vertx.eventBus
    var routeMatcher = new RouteMatcher

      // 기본 설정
    val config_ssky = new JsonObject()
    config_ssky.putString("url","http://api.ssky.io/") // URL 설정
    config_ssky.putString("host","localhost")         // 호스트 설정
    config_ssky.putNumber("port",8080)                // 포트 설정

    // 몽고DB 설정
    val config_database = new JsonObject()
    config_database.putString("address","ssky.mongo")
    config_database.putString("host","127.0.0.1")
    config_database.putNumber("port",27017)
    config_database.putNumber("pool_size",20)
    config_database.putString("db_name","test")

    // 초기화 작업
    serverlog("서버가 시작되었습니다.")
    container.deployModule("io.vertx~mod-mongo-persistor~2.0.0-final",config_database,1)
    eventbus.registerHandler("ssky.auth")(authHandle _)


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
    serverlog("서버가 정상적으로 실행되었습니다.")

  }

  // 서버 로그
  def serverlog(message:String){ println("[SSKY] " + message) }
  def handle(request:HttpServerRequest){ request.response.end("hello mod-lang-scala!!") }
  override def stop(){ serverlog("서버가 정상적으로 종료되었습니다.") }

}
