
import com.sun.xml.internal.fastinfoset.stax.events.EventBase
import org.vertx.java.busmods.BusModBase
import org.vertx.scala.platform.Verticle
import org.vertx.scala.core.eventbus._
import org.vertx.scala.core.json._

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
    vertx.eventBus.send("vertx.mongo",jsonData, (mongoMsg:Message[JsonObject])=>{
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

    })

  }

  //로그인
  def users_login(msg:Message[JsonObject]){

    val resultData = new JsonObject()
    val jsonData = new JsonObject("""{"action":"findone","collection":"User"}""")
    jsonData.putObject("matcher",new JsonObject("""{"username":""""+msg.body.getObject("document").getString("username")+""""}"""))

    vertx.eventBus.send("vertx.mongo",jsonData, (mongoMsg:Message[JsonObject])=>{
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

  // 이메일 전송부분쪽 해결 필요
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

    vertx.eventBus.send("vertx.mongo",jsonData, (mongoMsg:Message[JsonObject])=>{
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
    println(msg.body.getObject("document").getString("username"))
    jsonData.putObject("matcher",new JsonObject("""{"username":""""+msg.body.getObject("document").getString("username")+""""}"""))

    vertx.eventBus.send("vertx.mongo",jsonData, (mongoMsg:Message[JsonObject])=>{
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

          vertx.eventBus.send("vertx.mongo",jsonUpdateData, (mongoMsg:Message[JsonObject])=>{

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

  //회원정보쿼리
  def users_query(msg:Message[JsonObject]){

    val resultData = new JsonObject()
    val jsonData = new JsonObject("""{"action":"find","collection":"User"}""")
    jsonData.putString("matcher","")
    jsonData.putString("sort","")
    jsonData.putString("keys","")
    jsonData.putString("limit","0")

    vertx.eventBus.send("vertx.mongo",jsonData, (mongoMsg:Message[JsonObject])=>{


    })

  }

  //회원 탈퇴
  def users_delete(msg:Message[JsonObject]){

    val resultData = new JsonObject()
    val jsonData = new JsonObject("""{"action":"findone","collection":"User"}""")
    println(msg.body.getObject("document").getString("username"))
    jsonData.putObject("matcher",new JsonObject("""{"username":""""+msg.body.getObject("document").getString("username")+""""}"""))

    vertx.eventBus.send("vertx.mongo",jsonData, (mongoMsg:Message[JsonObject])=>{
      if(checkExist(mongoMsg)) {

        if(msg.body.getObject("document").getString("sessionToken") == mongoMsg.body.getObject("result").getString("sessionToken")) {

          val jsonDeleteData = new JsonObject("""{"action":"delete","collection":"User","matcher":{"username",""""+msg.body.getObject("document").getString("username")+
            """"}, "writeConcern" : "SAFE"}""")
          vertx.eventBus.send("vertx.mongo",jsonDeleteData, (mongoDelMsg:Message[JsonObject])=>{
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

  //SNS 연동
  def users_link(msg:Message[JsonObject]){


  }

  //Module Test
  def users_ping(msg:Message[JsonObject]){
    val pingReply = new JsonObject()
    pingReply.putString("action:","pong")
    pingReply.putString("time:",dateFormat.format(new Date))
    msg.reply(pingReply)
  }

  // Auth Event Handler
  def authHandle(msg:Message[JsonObject]){
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
      case "link" => users_link(msg)
      case "ping" => users_ping(msg)
    }
  }

  override def start()
  {
    vertx.eventBus.registerHandler("ssky.auth.manager",authHandle _)
    serverlog("Auth 서버가 정상적으로 실행되었습니다.")


  }


}
