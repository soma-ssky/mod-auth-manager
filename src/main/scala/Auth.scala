

import org.vertx.scala.platform.Verticle
import org.vertx.scala.core.eventbus._
import org.vertx.scala.core.json._
import org.vertx.scala.core.http._
import org.vertx.scala.core.buffer.Buffer

import java.util.Date                     // ISODate
import java.text.SimpleDateFormat         // ISODate

import java.security.SecureRandom;        // Session
import java.math.BigInteger;              // Session


class Auth extends Verticle{

  //////////////////////////////////////////////
  // User Module
  //////////////////////////////////////////////
  val dateFormat = new SimpleDateFormat("yyyy/MM/dd'T'HH:mm:ss.SSS'Z'")
  val random = new SecureRandom()
  def serverlog(message:String){ println("[SSKY_AUTH] " + message) }

  val THIS_ADDRESS = "ssky.auth.manager";
  val MONGO_ADDRESS = "vertx.mongo.persistor";

  def checkExist(msg:Message[JsonObject]):Boolean = {
    msg.body.getString("status").equals("ok") && (msg.body.getObject("result") != null)
  }

  case class ?:[T](x: T) {
    def apply(): T = x
    def apply[U >: Null](f: T => U): ?:[U] =
      if (x == null) ?:[U](null)
      else ?:[U](f(x))
  }

  //회원가입
  def users_signup(msg:Message[JsonObject]){

    val resultData = new JsonObject()
    val jsonData = new JsonObject("""{"action":"save","collection":"User"}""")

    //페이스북, SNS회원가입
    if(?:(msg.body)(_.getObject("document"))(_.getObject("authData"))(_.getObject("facebook"))() != null){

      val jsonSearch = new JsonObject("""{"action":"findone","collection":"User"}""")
      jsonSearch.putObject("matcher",new JsonObject(
        """{"authData":{"facebook":{"id":""""+msg.body.getObject("document").getObject("authData").getObject("facebook").getString("id")+"""",
       "access_token":"""" + msg.body.getObject("document").getObject("authData").getObject("facebook").getString("access_token")+""""}}}"""))

      vertx.eventBus.send(MONGO_ADDRESS, jsonSearch, (mongoRep:Message[JsonObject])=>{
        if(checkExist(mongoRep)) {
          println("exsist")
          return
        } else {
          println("no_exsist")
          msg.body.getObject("document").putString("username",new BigInteger(130, random).toString(25))
          msg.body.getObject("document").putString("password",new BigInteger(130, random).toString(25))
        }
      })
    }

    //회원의 기본적인 데이터 입력
    msg.body.getObject("document").putString("createdAt",dateFormat.format(new Date))
    msg.body.getObject("document").putString("updatedAt",dateFormat.format(new Date))
    msg.body.getObject("document").putString("sessionToken",new BigInteger(130, random).toString(25))
    msg.body.getObject("document").putString("bcryptPassword",BCrypt.hashpw(msg.body.getObject("document").getString("password"),BCrypt.gensalt() ))

    msg.body.getObject("document").removeField("password")
    msg.body.getObject("document").removeField("_id")

    jsonData.putObject("document",msg.body.getObject("document"))

    vertx.eventBus.send(MONGO_ADDRESS, jsonData, (mongoMsg:Message[JsonObject])=>{

        resultData.putString("objectId",mongoMsg.body.getString("_id"))
        resultData.putString("createdAt",msg.body.getObject("document").getString("createdAt"))
        resultData.putString("sessionToken",msg.body.getObject("document").getString("sessionToken"))
        msg.reply(resultData)

        //resultData.putString("code","202")
        //resultData.putString("error","username "+msg.body.getObject("document").getString("username")+" already taken")
        //msg.reply(resultData)
    })


  }

  //로그인
  def users_login(msg:Message[JsonObject]){


    val resultData = new JsonObject()
    val jsonData = new JsonObject("""{"action":"findone","collection":"User"}""")
    jsonData.putObject("matcher",new JsonObject("""{"username":""""+msg.body.getObject("document").getString("username")+""""}"""))

    vertx.eventBus.send(MONGO_ADDRESS,jsonData, (mongoMsg:Message[JsonObject])=>{
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
    })

  }

  // 이메일 전송부분
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

    vertx.eventBus.send(MONGO_ADDRESS,jsonData, (mongoMsg:Message[JsonObject])=>{
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
    })

  }

  //회원정보 수정
  def users_update(msg:Message[JsonObject]){
    val resultData = new JsonObject()
    val jsonData = new JsonObject("""{"action":"findone","collection":"User"}""")
    jsonData.putObject("matcher",new JsonObject("""{"username":""""+msg.body.getObject("document").getString("username")+""""}"""))

    vertx.eventBus.send(MONGO_ADDRESS,jsonData, (mongoMsg:Message[JsonObject])=>{
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

          vertx.eventBus.send(MONGO_ADDRESS,jsonUpdateData, (mongoMsg:Message[JsonObject])=>{
            resultData.putString("updatedAt",msg.body.getObject("document").getString("updatedAt"))
            //비밀번호가 변경되면 세션도 다시 지정함.
            if(ChangePasswd) resultData.putString("sessionToken",msg.body.getObject("document").getString("sessionToken"))
            msg.reply(resultData)

          })

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
    })

  }

  //회원 탈퇴
  def users_delete(msg:Message[JsonObject]){

    val resultData = new JsonObject()
    val jsonData = new JsonObject("""{"action":"findone","collection":"User"}""")
    jsonData.putObject("matcher",new JsonObject("""{"username":""""+msg.body.getObject("document").getString("username")+""""}"""))

    vertx.eventBus.send(MONGO_ADDRESS,jsonData, (mongoMsg:Message[JsonObject])=>{
      if(checkExist(mongoMsg)) {

        if(msg.body.getObject("document").getString("sessionToken") == mongoMsg.body.getObject("result").getString("sessionToken")) {
          val jsonDeleteData = new JsonObject("""{"action":"delete","collection":"User","matcher":{"username",""""+msg.body.getObject("document").getString("username")+
            """"}, "writeConcern" : "SAFE"}""")
          vertx.eventBus.send(MONGO_ADDRESS,jsonDeleteData, (mongoDelMsg:Message[JsonObject])=>{
            msg.reply(mongoDelMsg.body.getObject("result"))
          })
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
    })

  }

  // User Data Query
  def users_query(msg:Message[JsonObject]){


  }

  //Module Test
  def users_ping(msg:Message[JsonObject]){
    val pingReply = new JsonObject()
    pingReply.putString("action:","pong")
    pingReply.putString("time:",dateFormat.format(new Date))
    msg.reply(pingReply)
  }

  // Auth Event Handler
  def authHandle( msg:Message[JsonObject] ){
    val event = msg.body.getString("action")

    event match{
      case "signup" => users_signup(msg)
      case "login" => users_login(msg)
      case "verifyingEmail" => users_verifyingEmail(msg)
      case "resetPassword" => users_resetPassword(msg)
      case "retrieve" => users_retrieve(msg)
      case "update" => users_update(msg)
      case "query" => users_query(msg)
      case "delete" => users_delete(msg)
      case "ping" => users_ping(msg)
    }

  }

  var config = new JsonObject
  override def start()
  {

    // 몽고DB 설정
    val config_database = new JsonObject()
    config_database.putString("address",MONGO_ADDRESS)
    config_database.putString("host","127.0.0.1")
    config_database.putNumber("port",27017)
    config_database.putNumber("pool_size",20)
    config_database.putString("db_name","test")
    container.deployModule("io.vertx~mod-mongo-persistor~2.0.0-final",config_database,1)

    config = container.config()
    println("Config is " + config.toString);

    vertx.eventBus.registerHandler(THIS_ADDRESS, authHandle _)

    val eventbus = vertx.eventBus
    var routeMatcher = new RouteMatcher

    //Signing Up
    routeMatcher.post("/:version/users", (req:HttpServerRequest)=>{



      req.dataHandler( (data:Buffer) => {
        val sendJson = new JsonObject("""{"action":"signup","document":"""+data.toString()+"""}""")
        eventbus.send(THIS_ADDRESS,sendJson , (msg:Message[JsonObject])=>{
          req.response().putHeader("Access-Control-Allow-Origin","*")
          req.response().putHeader("Content-Type","application/json")
          req.response().putHeader("Location","http://localhost:8080/1/users/" + msg.body.getString("objectId"))
          req.response().end(msg.body.toString)
        })
      })

      /*
      val urlParams = req.params
      val userData = new JsonObject
      userData.putString("username",urlParams("username").head)
      userData.putString("password",urlParams("password").head)

      val sendJson = new JsonObject("""{"action":"login"}""")
      sendJson.putObject("document",userData)

      eventbus.send(THIS_ADDRESS, sendJson, (msg:Message[JsonObject])=>{
        req.response().end(msg.body.toString)
      })           */






    })

    routeMatcher.post("/:version/login", (req:HttpServerRequest)=>{

      req.dataHandler( (data:Buffer) => {
        val sendJson = new JsonObject("""{"action":"login","document":"""+data.toString()+"""}""")
        eventbus.send(THIS_ADDRESS, sendJson, (msg:Message[JsonObject])=>{
          req.response().putHeader("Access-Control-Allow-Origin","*")
          req.response().putHeader("Content-Type","application/json")
          req.response().putHeader("Location","http://localhost:8080/1/users/" + msg.body.getString("objectId"))
          req.response().end(msg.body.toString)
        })
      })

      /*
      val urlParams = req.params
      val userData = new JsonObject
      userData.putString("username",urlParams("username").head)
      userData.putString("password",urlParams("password").head)

      val sendJson = new JsonObject("""{"action":"login"}""")
      sendJson.putObject("document",userData)

      eventbus.send(THIS_ADDRESS, sendJson, (msg:Message[JsonObject])=>{
        req.response().end(msg.body.toString)
      })

      */

    })




    //Retrieving Users
    routeMatcher.get("/:version/users/:id", (req:HttpServerRequest) =>{

      val urlParams = req.params
      val userData = new JsonObject
      userData.putString("objectId",urlParams("id").head)

      val sendJson = new JsonObject("""{"type":"retrieve"}""")
      sendJson.putObject("document",userData)

      eventbus.send("ssky.auth",sendJson, (msg:Message[JsonObject])=>{
        req.response().end(msg.body.toString)
      })

    })




    vertx.createHttpServer.requestHandler(routeMatcher).listen(8080)
    serverlog("Auth 서버가 정상적으로 실행되었습니다.")
  }

}
