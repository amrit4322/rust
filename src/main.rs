#![feature(proc_macro_hygiene, decl_macro)]

#[macro_use] extern crate rocket;
extern crate bcrypt;
extern crate tokio;

use mongodb::{bson, options::{UpdateOptions,FindOptions,ClientOptions, ServerApi, ServerApiVersion}, Client};
use std::{time::Duration};
use std::sync::{Arc,Mutex};
use tokio::time::timeout;
use mongodb::error::Result as MongoResult;
use mongodb::Client as ClientData;
use rocket::{request::Request,response::{self, Responder, Response},State, fs::FileName};
// use rocket::response::NamedFile;
use rocket::data::{ByteUnit};
use rocket::form::{DataField,Form, Contextual, FromForm, FromFormField, Context};
use serde::{Serialize,Deserialize};
use rocket_dyn_templates::{Template, context};
use futures::stream::{StreamExt, TryStreamExt};
use bcrypt::{hash,verify,DEFAULT_COST};
use std::io::Cursor;
use rocket::http::{ContentType, Status};
use serde_json;
use rocket::fs::{FileServer, TempFile, relative};
use mongodb::bson::oid::ObjectId;
use std::collections::HashMap;

// use serde_json::to_document;


#[derive(Debug, Serialize, FromForm,Deserialize,Clone)]
struct ValidationResult {
    success: bool,
    errors: HashMap<String, String>,
}
impl ValidationResult {
    fn new() -> Self {
        ValidationResult {
            success: true,
            errors: HashMap::new(),
        }
    }

    fn add_error(&mut self, field: &str, message: &str) {
        self.success = false;
        self.errors.insert(field.to_string(), message.to_string());
    }
}
#[derive(Debug, Serialize, FromForm,Deserialize,Clone)]
  struct User{
    
  // #[field(validate = len(1..).or_else(msg!("invalid username")))]
    username:String,
  // #[field(validate = len(1..))]
    firstname:String,
    lastname:String,
  // #[field(validate =range(0..=120).or_else(msg!("Age should be between 0 to 120")))]
    age:u32,
  // #[field(validate = contains('@').or_else(msg!("invalid email address")))]
    email:String,
   // #[field(validate = len(6..40))]
     password:String,
     
}
impl User{
    fn validate(&self) -> ValidationResult {
        let mut result = ValidationResult::new();

        if self.username.is_empty() {
            result.add_error("username", "Username is required");
        }

        if self.firstname.is_empty() {
            result.add_error("firstname", "Firstname is required");
        }
        if !(1..150).contains(&self.age){
            result.add_error("age", "Age should be between 0 to 150");
        }
        if !self.email.contains("@"){
            result.add_error("email", "Invalid Email");
        }
        if self.password.len()<6{
            result.add_error("password", "Password too  short");
        }
        // Add validation for other fields here...

        result
    }
}
#[derive(Debug, Serialize,Deserialize,Clone)]
struct UserMod{
    #[serde(rename = "_id",skip_serializing_if = "Option::is_none")]
    id: Option<ObjectId>,
    username:String,
    firstname:String,
    lastname:String,
    age:u32,
    email:String,
    password:String,
    filepath:String
}

#[derive(Debug, Serialize, FromForm,Deserialize,Clone)]
struct UserUpdate{
    firstname:String,
    lastname:String,
    email:String,
    password:String,
}

#[derive(Debug, FromForm)]
struct UploadFile<'f>{
   
    upload:Option<TempFile<'f>>
}

#[derive(Debug, Serialize, FromForm,Deserialize,Clone)]
struct UserResponse{
    user:User
}



#[derive(Debug, Serialize)]
struct JsonResponse<T> {
    status: &'static str,
    message:&'static str,
    data: T,
}

impl<'r, T: Serialize> Responder<'r, 'static> for JsonResponse<T> {
    fn respond_to(self, _: &'r Request<'_>) -> response::Result<'static> {
        let json = serde_json::to_string(&self).map_err(|e| {
            println!("Failed to serialize JSON: {:?}", e);
            Status::InternalServerError
        })?;

        Response::build()
            .status(Status::Ok)
            .header(ContentType::JSON)
            .sized_body(None,Cursor::new(json))
            .ok()
    }
}


#[derive(Debug, Clone)]
struct Datauser{
    user_name:Arc<Mutex<String>>,
    user_details:Arc<Mutex<User>>,
    client: ClientData
}

#[derive(Debug,Serialize, Deserialize,FromForm,Clone)]

struct Formdata{
    username:String,
    password:String,
}

#[derive(Debug,Serialize, Deserialize,FromForm,Clone)]
//#[allow(dead_code)]
struct FindUser{
    #[field(validate = len(1..))]
    username:String
}

//errors
#[catch(404)]
fn error_page() -> Template {
    Template::render("error",context!{data:"Error found 404"})
}

//initializing the project 
#[tokio::main]
async fn main(){
    println!("starting the project");
    let client=connect().await;
    let mut data_set:Datauser;
    match client{
    Ok(client_conn)=>{
        data_set = Datauser{

        user_name:Arc::new(Mutex::new(String::from(""))),
        user_details:Arc::new(Mutex::new(User{
            username:String::new(),
            firstname:String::new(),
            lastname:String::new(),
            age:0,
            email:String::new(),
            password:String::new(),
        })),
        client:client_conn.clone()
        };
        rocket::build()
            .manage(data_set)
            .mount("/",routes![index,login_check, register_page,register_check,update_page,update_details,delete_acc,delete_account,patch_details,upload,upload_page,uploadfile_update,read_file])
            .mount("/", FileServer::from(relative!("uploads")))
           
            .attach(Template::fairing())
            .register("/",catchers![error_page])
            .launch()
            .await
            .expect("Rocket crashed");

    }
    Err(error)=>{
        println!("Error while connecting the mongodb {:?}",error);
    }
    
    }
   
   
}


//connecting with mongodb 
async fn connect()-> MongoResult<ClientData> {
  let mut client_options =ClientOptions::parse("<mongodb url>").await?;
  let server_api = ServerApi::builder().version(ServerApiVersion::V1).build();
  client_options.server_api = Some(server_api);
  let client = Client::with_options(client_options)?;
  println!("connected with mongodb");
  Ok(client)
  

  
}



//index page
#[get("/")]
async fn index()->Template{   
    Template::render("login",context!{})
}


//get upload
#[get("/upload")]
async fn upload_page()->Template{   
    Template::render("uploadform",context!{})
}

#[patch("/upload/<path>",data="<form>")]
async fn uploadfile_update(path:String,mut form:Form<UploadFile<'_>>,state: &State<Datauser>)->JsonResponse<Result<String,&'static str>>{    
    if  let Some(ref mut file) = form.upload {
        // Specify the target directory where you want to save the uploaded file
        println!("File is {:#?}",file);
        let filedata = file.path();
        println!("file path  {:#?} ",filedata);
        let filedata = file.raw_name();
        match filedata{
            Some(file_name)=>{
                let name = file_name.dangerous_unsafe_unsanitized_raw();
                println!("File namme found is {:#?}",name);
                let target_directory = "C:\\Users\\aj044\\OneDrive\\Desktop\\uploads";
                println!("target {:?}", target_directory);
                // Generate a unique file name to prevent overwrites (you can use other methods if needed)
                let file_path = format!("{}\\{}", target_directory,name);
                println!("file_name {}",file_path);
                // Save the uploaded file to the specified directory
                let check =file.persist_to(&file_path).await ;
                match check{
                    Ok(succ)=>{
                        println!("File uploaded {:?}",succ);
                        let client = &state.client;
                        let db = client.database("userData");
                        let collection = db.collection::<User>("users");
                        let  id=path;
                        if id.is_empty(){
                            return JsonResponse {
                                status: "error",
                                message:"Missing path",
                                data: Err("Invalid path"),
                            };
                        }
                        let id= Some(ObjectId::parse_str(&id).unwrap());
                       
                        let filter =bson::doc!{"_id":id};
                        let update = bson::doc!{
                            "$set": { 
                                "filepath":&file_path,
                                
                             } };
                        //let update = bson::doc! {form.clone()  };
                        let options = UpdateOptions::builder()
                            .upsert(false) // Set to true if you want to upsert (insert if not found)
                            .build();
                        
                        let handle  = tokio::task::spawn(async move{
                            let _=collection.update_one(filter, update, options).await;
                        });
                        
                        match timeout(Duration::from_secs(5), handle).await {
                            Ok(result)=>{
                       
                                println!("User updated successfully! {:#?}",result);
                                return JsonResponse {
                                    status: "success",
                                    message:"User updated successfully!",
                                    data: Ok(file_path),
                                };
                                //Template::render("dashboard", context!{data:"User updated successfully!"})
                            }
                        
                            Err(error)=>{  println!("No matching user found.{:?}",error);
                                return JsonResponse {
                                    status: "error",
                                    message:"No matching user found.",
                                    data: Err("Invalid credentials"),
                                };
                                //template::render("dashboard", context!{data:"No matching user found."})
                            }   
                        }
                    }Err(error)=>{
                        println!("Error {:?}",error);
                    }
                }
                println!("Successs");
    
                JsonResponse {
                    status: "error",
                    message:"No matching user found.",
                    data: Err("Invalid credentials"),
                }
                 
            }
            None=>{
                println!("No file name");
                JsonResponse {
                    status: "error",
                    message:"No matching user found.",
                    data: Err("Invalid credentials"),
                }
            }
        }
        
       
    } else {
        println!("failure");
        JsonResponse {
            status: "error",
            message:"No matching user found.",
            data: Err("Invalid credentials"),
        }
    }
}







//upload file
#[post("/upload", data = "<form>")]
async fn upload(mut form: Form<UploadFile<'_>>) -> Result<(),()> { 
    
    
    println!("form is   {:?}",&form);
    if  let Some(ref mut file) = form.upload {
        // Specify the target directory where you want to save the uploaded file
        println!("File is {:#?}",file);
        let filedata = file.path();
        println!("file path  {:#?} ",filedata);
        let filedata = file.raw_name();
        match filedata{
            Some(file_name)=>{
                let name = file_name.dangerous_unsafe_unsanitized_raw();
                println!("File namme found is {:#?}",name);
                let target_directory = "C:\\Users\\aj044\\OneDrive\\Desktop\\uploads";
                println!("target {:?}", target_directory);
                // Generate a unique file name to prevent overwrites (you can use other methods if needed)
                let file_path = format!("{}\\{}", target_directory,name);
                println!("file_name {}",file_path);
                // Save the uploaded file to the specified directory
                let check =file.persist_to(&file_path).await ;
                match check{
                    Ok(succ)=>{
                        println!("File uploaded {:?}",succ);
                       

                    }Err(error)=>{
                        println!("Error {:?}",error);
                    }
                }
                println!("Successs");
    
                Ok(())
                 
            }
            None=>{
                println!("No file name");
                Err(())
            }
        }
        
       
    } else {
        println!("failure");
        Err(())
    }

}


//download verificiation  There are other method for downloading the file. This is just the basic one
#[post("/download/<path>")]
async fn read_file(path:String,state: &State<Datauser>)->JsonResponse<Result<UserMod,&'static str>>{    
    let client = &state.client;
    let db = client.database("userData");
    let collection = db.collection::<UserMod>("users");
    let  id=path;

    if id.is_empty(){
        return JsonResponse {
            status: "error",
            message:"Missing path",
            data: Err("Invalid path"),
        };
    }
    let id= Some(ObjectId::parse_str(&id).unwrap());
    let filter =bson::doc!{"_id":id};
    let find_options = FindOptions::builder().build();
    let mut data_set :Vec<UserMod> = vec![];
    let mut cursor  = collection.find(filter,find_options).await;
    while let Some(result) = cursor.as_mut().expect("Reason").next().await{
        match result{
            Ok(doc)=>{
                println!("Docs are  {:#?}",doc.clone());
                data_set.push(doc.clone());
            }
            Err(error)=>{
                println!("Error found while fetching {:?}",error);
            }
        }
    }
    
    if data_set.len()==0{
      
        return JsonResponse {
            status: "error",
            message:"User not found",
            data: Err("Invalid username"),
        };
    }else{
        let userdata = data_set[0].clone();
        println!("User data is {:#?} ",userdata);
         let file_path = userdata.filepath.clone();
       
        
        match std::fs::read(&file_path) {
                Ok(file_contents) => {
                    println!("File contents: {:?}", file_contents);
            
                  
                    
                }
                Err(error) => {
                    println!("Error reading file: {:?}", error);
                    
                }
            }
       
      
            JsonResponse {
                status: "success",
                message:"Login Successfull",
                data: Ok(userdata.clone()),
            }
           
        
    }
    
}






//login verificiation
#[post("/login",data="<form>")]
async fn login_check(form:Form<Formdata>,state: &State<Datauser>)->JsonResponse<Result<UserMod,&'static str>>{    
    let client = &state.client;
    let db = client.database("userData");
    let collection = db.collection::<UserMod>("users");
    let filter =bson::doc!{"username":form.username.clone()};
    let find_options = FindOptions::builder().build();
    let mut data_set :Vec<UserMod> = vec![];
    let mut cursor  = collection.find(filter,find_options).await;
    while let Some(result) = cursor.as_mut().expect("Reason").next().await{
        match result{
            Ok(doc)=>{
                println!("Docs are  {:#?}",doc.clone());
                data_set.push(doc.clone());
            }
            Err(error)=>{
                println!("Error found while fetching {:?}",error);
            }
        }
    }
    
    if data_set.len()==0{
      
        return JsonResponse {
            status: "error",
            message:"Username not found! Please Register first",
            data: Err("Invalid username"),
        };
    }else{
        let userdata = data_set[0].clone();
        println!("User data is {:#?} ",userdata);
        let verified = verify(form.password.clone(),&userdata.password).unwrap();
        println!("Password verification {:?}",verified);
        if verified {
            let mut user  = state.user_name.lock().unwrap();
            *user = String::from(userdata.firstname.clone());
            // let mut user_det = state.user_details.lock().unwrap();
            // *user_det =userdata.clone();
          
            JsonResponse {
                status: "success",
                message:"Login Successfull",
                data: Ok(userdata.clone()),
            }
            //Template::render("dashboard",context!{data: "Login Successfull"})
        }else{
            
               JsonResponse {
                status: "error",
                message:"Password doesn't match",
                data: Err("Invalid Password"),
            }
        }
    }
    
}


//index page
#[get("/registration")]
async fn register_page()->Template{   
    Template::render("register",context!{})
}



fn validating(form:Form<User>,state: &State<Datauser>)->Result<User,JsonResponse<ValidationResult>>{ 
    
    let user = form.into_inner();
    let validation_result = user.validate();
    println!("Validation give us {:#?}",user);
    if validation_result.success {
        
   
        return  Ok(user);
       
    } else {
        
        return Err(JsonResponse {
            status: "error",
            message:"no success",
            data: validation_result,
        });
    }
     

   
     
}

//login verificiation
#[post("/registration",data="<form>")]
async fn register_check(form:Form<User>,state: &State<Datauser>)->JsonResponse<Result<UserMod,&'static str>>{   
  
    let client = &state.client;
    let db = client.database("userData");
    let collection = db.collection::<UserMod>("users");
    let filter =bson::doc!{"username":form.username.clone()};
    let find_options = FindOptions::builder().build();
    let mut data_set :Vec<UserMod> = vec![];
    let mut cursor  = collection.find(filter,find_options).await;
    while let Some(result) = cursor.as_mut().expect("Reason").next().await{
        match result{
            Ok(doc)=>{
                println!("Docs are  {:#?}",doc.clone());
                data_set.push(doc.clone());
            }
            Err(error)=>{
                println!("Error found while fetching {:?}",error);
            }
        }
    }
    
    if data_set.len()==0{
    
        let mut data = UserMod{
            id:None,
            username:form.username.clone(),
            firstname:form.firstname.clone(),
            lastname:form.lastname.clone(),
            age:form.age.clone(),
            email:form.email.clone(),
            password:form.password.clone(),
            filepath:String::new()
        };
       let fetchdata=data.clone();
        data.password = hash(data.password.clone(),DEFAULT_COST).unwrap();
        let handle  = tokio::task::spawn(async move{
        collection.insert_one(data.clone(), None).await
        });
    
        match timeout(Duration::from_secs(5), handle).await {
    
            Ok(result) => {
                // Handle the result of the spawned task.
                println!("{:?}",result);
                println!("Success");
                return   JsonResponse {
                    status: "success",
                    message:"Registered Successfull",
                    data: Ok(fetchdata.clone()),
                };
               
            }
            Err(_) => {
                eprintln!("Task timed out.");
                return JsonResponse {
                    status: "error",
                    message:"Registered Again !! Time out Error",
                    data: Err("Session time out"),
                } ;
                
                // Handle the timeout error.
                }
        }
       
    }else{
        return  JsonResponse {
            status: "error",
            message:"Username name already exist",
            data: Err("Invalid credentials"),
        } ;
     
    }
   
    
}




#[get("/update")]
async fn update_page(state:&State<Datauser>)->Template{  
    let user_name = state.user_name.lock().unwrap();
    println!("checking {}",user_name);
    let user_det =state.user_details.lock().unwrap().clone(); 
    println!("data to update {:#? }",user_det);  
    Template::render("update",context!{user_det :user_det})
}

#[patch("/update/<path>",data="<form>")]
async fn patch_details(path:String,form:Form<UserUpdate>,state: &State<Datauser>)->JsonResponse<Result<UserUpdate,&'static str>>{    
    let client = &state.client;
    let db = client.database("userData");
    let collection = db.collection::<User>("users");
    let  id=path;
    if id.is_empty(){
        return JsonResponse {
            status: "error",
            message:"Missing path",
            data: Err("Invalid path"),
        };
    }
    let id= Some(ObjectId::parse_str(&id).unwrap());
   
    let filter =bson::doc!{"_id":id};
    let update = bson::doc!{
        "$set": { 
            "firstname":form.firstname.clone(),
            "lastname":form.lastname.clone(),
            "password": hash(form.password.clone(),DEFAULT_COST).unwrap(),
            "email":form.email.clone()
         } };
    
    let options = UpdateOptions::builder()
        .upsert(false) // Set to true if you want to upsert (insert if not found)
        .build();
    
    let handle  = tokio::task::spawn(async move{
        let _=collection.update_one(filter, update, options).await;
    });
    
    match timeout(Duration::from_secs(5), handle).await {
        Ok(result)=>{
   
            println!("User updated successfully! {:#?}",result);
            JsonResponse {
                status: "success",
                message:"User updated successfully!",
                data: Ok(form.clone()),
            }
           
        }
    
        Err(error)=>{  println!("No matching user found.{:?}",error);
            JsonResponse {
                status: "error",
                message:"No matching user found.",
                data: Err("Invalid credentials"),
            }
           
        }   
    }
}
    



#[put("/update/<path>",data="<form>")]
async fn update_details(path:String,form:Form<User>,state: &State<Datauser>)->JsonResponse<Result<User,&'static str>>{    
    let client = &state.client;
    let db = client.database("userData");
    let collection = db.collection::<User>("users");
    let  id=path;
    if id.is_empty(){
        return JsonResponse {
            status: "error",
            message:"Missing path",
            data: Err("Invalid path"),
        };
    }
    let id= Some(ObjectId::parse_str(&id).unwrap());
    let filter =bson::doc!{"_id":id};
  
      
      let update = bson::doc!{
        "$set": { 
            "username":form.username.clone(),
            "firstname":form.firstname.clone(),
            "lastname":form.lastname.clone(),
            "password": hash(form.password.clone(),DEFAULT_COST).unwrap(),
            "email":form.email.clone(),
            "age":form.age.clone(),
         } };
   
    let options = UpdateOptions::builder()
        .upsert(false) // Set to true if you want to upsert (insert if not found)
        .build();
    
    let handle  = tokio::task::spawn(async move{
        let _=collection.update_one(filter, update, options).await;
    });
    
    match timeout(Duration::from_secs(5), handle).await {
        Ok(result)=>{
   
            println!("User updated successfully! {:#?}",result);
            JsonResponse {
                status: "success",
                message:"User updated successfully!",
                data: Ok(form.clone()),
            }
           
        }
    
        Err(error)=>{  println!("No matching user found.{:?}",error);
            JsonResponse {
                status: "error",
                message:"No matching user found.",
                data: Err("Invalid credentials"),
            }
            
        }   
    }
}
    

#[post("/delete",data="<form>")]
async fn delete_acc(form:Form<User>,state: &State<Datauser>)->JsonResponse<Result<&'static str,&'static str>>{    
    let client = &state.client;
    let db = client.database("userData");
    let collection = db.collection::<User>("users");
    let filter =bson::doc!{"username":form.username.clone()};
   
    
 
    
    let handle  = tokio::task::spawn(async move{
        let _=collection.delete_one(filter, None).await;
    });
    
    match timeout(Duration::from_secs(5), handle).await {
        Ok(result)=>{
   
            println!("User Deleted successfully! {:#?}",result);
                JsonResponse {
                    status: "sucess",
                    message:"User Deleted successfully!",
                    data: Ok("Deleted"),
                }
         
        }
    
        Err(error)=>{  println!("No matching user found.{:?}",error);
            JsonResponse {
                status: "error",
                message:"Failed to delete user",
                data: Err("Invalid credentials"),
            }
           
        }   
    }
}
    

    
#[delete("/delete/<path>")]
async fn delete_account(path :String ,state: &State<Datauser>)->JsonResponse<Result<&'static str,&'static str>>{    
    let client = &state.client;
    let db = client.database("userData");
    let collection = db.collection::<User>("users");
    let  id=path;
    if id.is_empty(){
        return JsonResponse {
            status: "error",
            message:"Missing path",
            data: Err("Invalid path"),
        };
    }
    let id= Some(ObjectId::parse_str(&id).unwrap());
    let filter =bson::doc!{"_id":id};

    let handle  = tokio::task::spawn(async move{
        let _=collection.delete_one(filter, None).await;
    });
    
    match timeout(Duration::from_secs(5), handle).await {
        Ok(result)=>{
   
            println!("User Deleted successfully! {:#?}",result);
            JsonResponse {
                status: "success",
                message:"User Deleted successfully!",
                data: Ok("Deleted"),
            }
            
           
        }
    
        Err(error)=>{  println!("No matching user found.{:?}",error);
            JsonResponse {
                status: "error",
                message:"Failed to delete user",
                data: Err("Invalid credentials"),
            }
           
        }
    }
}
