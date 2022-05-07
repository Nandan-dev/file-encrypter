use aes_gcm_siv::{Key, Aes256GcmSiv, Nonce};
use aes_gcm_siv::aead::NewAead;
use aes_gcm_siv::aead::Aead;
use blake2b_simd::Params;
use orion::hash::{Digest, digest};
use orion::hazardous::stream::chacha20::encrypt;


use std::fs;
use std::fs::{File, read_to_string};
use std::io::{Bytes, Write, BufReader, BufRead, BufWriter, Read, };
use std::error::Error;
use std::collections::HashSet;

use std::io;

use eframe::epi::{App, Frame};
use eframe::{NativeOptions, run_native};
use egui::{CentralPanel, Context, Ui, RichText, menu, ComboBox};
use orion::{kdf, hash};
use orion::kdf::{Password, SecretKey};
use orion::aead;

#[derive(PartialEq)]
enum mode {enc , dec}
#[derive(PartialEq, Debug)]
enum encmode {twofish , aes256}

struct encbtn {
    finalmode: mode,
    picked_path: Option<String>,
    outpath: Option<String>,
    outname: String,
    password: String,
    hashpass: bool,
    encryptionmethod: encmode,
    hidepass: bool,
    jsonsettings: String,
    jsonvisible: bool,
    // jsonfile: File,
}

impl Default for encbtn {
    fn default() -> Self {
        Self {
            finalmode: mode::enc,
            picked_path: Some("nothing selected".to_string()),
            outpath: Some("Nothing selected".to_string()),
            outname: String::from("output.txt"),
            password: String::from("password123"),
            hashpass: true,
            encryptionmethod: encmode::aes256,
            hidepass: true,
            jsonsettings: match (read_to_string("./config.json")) {
                Ok(T) => T,
                Err(E) => {"
                {
                    \"twofish\" : {
                        \"salt\" : \"This is an amazing salt lololol this can be hover ever long as u want \",
                        \"iterations\" : 3,
                        \"memory\" : 1024,
                        \"length\" : 32
                    },

                    \"aes256gcmsiv\" {
                        \"personal\" : \"1$TEl5WXdiaHBCM\",
                        \"salt\" : \"mxjZURQVA$IU3Srw\",
                        \"nonceslice\" : \"GS2x3Yw$5ZXP\"
                    }

                }
                ".to_string()},
            },
            jsonvisible: false,
            // jsonfile: File::open("./config.json").unwrap()
        }
    }
}

impl App for encbtn {

    



    fn update(&mut self, ctx: &Context, frame: &Frame) {

        CentralPanel::default().show(&ctx , |ui| {
           

            ui.horizontal(|ui| {
               
                
                
                ui.vertical_centered(|ui| {
                    ui.label(RichText::new("File encrypter").font(egui::FontId::proportional(40.0)));
                    
                });
                
            });
            

            ui.horizontal(|ui| {
                ui.monospace("Enter Password : ");

               ui.add(egui::TextEdit::singleline(&mut self.password).password(self.hidepass));

                ui.checkbox(&mut self.hidepass, "Hide password : ");

            });

            ui.monospace("Current mode : ");
            
            
            ui.horizontal(|ui| {
                if ui.add(egui::RadioButton::new(self.finalmode == mode::enc, "Encrypt File")).clicked() {
                    self.finalmode = mode::enc;
                }
                if ui.add(egui::RadioButton::new(self.finalmode == mode::dec, "Decrypt File")).clicked() {
                    self.finalmode = mode::dec;
                }
                ui.label("Select Encryption Method -> ");
                ComboBox::from_label("").selected_text(format!("{:#?}",self.encryptionmethod)).show_ui(ui,|ui|{
                    ui.selectable_value(&mut self.encryptionmethod, encmode::twofish, "Twofish with argon2 hashing");
                    ui.selectable_value(&mut self.encryptionmethod, encmode::aes256, "Aes 256 Gcm Siv with blake2b hashing");
                });
            });

            ui.monospace("Input file : ");


            ui.horizontal(|ui| {
                if ui.button("Select input file ").clicked() {
                    if let Some(path) = rfd::FileDialog::new().pick_file() {
                        self.picked_path = Some(path.display().to_string())
                    }
                }

                
            });



            ui.label(self.picked_path.as_ref().unwrap());
            ui.monospace("Output File : ");
            if ui.button("Save output File").clicked() {
                if let Some(path) = rfd::FileDialog::new().save_file() {
                    self.outpath = Some(path.display().to_string())
                }
            }
            ui.label(self.outpath.as_ref().unwrap());

            if ui.button("Start Operation").clicked() {
                if self.finalmode == mode::enc {
                    if (self.encryptionmethod == encmode::aes256) {
                        encaes256(String::from(&self.password), self.picked_path.as_ref().unwrap(), self.outpath.as_ref().unwrap());
                    } else if (self.encryptionmethod == encmode::twofish) {
                        guienc(String::from(&self.password),self.picked_path.as_ref().unwrap() , self.outpath.as_ref().unwrap(), self.hashpass);
                    }
                } else if self.finalmode == mode::dec {
                    if (self.encryptionmethod == encmode::aes256) {
                        decaes256(String::from(&self.password), self.picked_path.as_ref().unwrap(), self.outpath.as_ref().unwrap());
                    } else if (self.encryptionmethod == encmode::twofish) {
                        guidec(String::from(&self.password), self.picked_path.as_ref().unwrap(), self.outpath.as_ref().unwrap(),self.hashpass)
                    }
                }
            }

            
            ui.checkbox(&mut self.jsonvisible, "show advanced settings (JSON FILE)");
            ui.set_visible(self.jsonvisible);
            egui::ScrollArea::vertical().show(ui, |ui| {
                ui.add(
                    egui::TextEdit::multiline(&mut self.jsonsettings)
                    .font(egui::TextStyle::Heading)
                    .code_editor()
                )
            });
            if (ui.button("save").clicked()) {
                File::create("./config.json").unwrap().write_all(self.jsonsettings.as_bytes());
            }

        });
    }

    fn name(&self) -> &str {
        "File Encrypter 💳💵💀💸"
    }
}



fn main() {

    let app = encbtn::default();
    let win_option = NativeOptions::default();
    run_native(Box::new(app) , win_option);
}

fn guienc(password: String, infile: &String , outfile: &String, hashpass: bool) {

    let jsonfile = match (read_to_string("./config.json")) {
        Ok(T) => T,
        Err(e) => "
        {
            \"twofish\" : {
                \"salt\" : \"This is an amazing salt lololol this can be hover ever long as u want \",
                \"iterations\" : 3,
                \"memory\" : 1024,
                \"length\" : 32
            }
        }
        ".to_string(),
    };
    
    let jsoncontents: serde_json::Value  = serde_json::from_str(&jsonfile.as_str()).unwrap();
    let settings = jsoncontents.get("twofish").unwrap();
    let salt = kdf::Salt::from_slice(settings.get("salt").unwrap().to_string().as_bytes()).unwrap();
    let mut pass = kdf::Password::from_slice(password.clone().as_bytes()).unwrap();
    let mut key = kdf::derive_key(&pass, &salt, settings.get("iterations").unwrap().to_string().trim().parse().unwrap(), settings.get("memory").unwrap().to_string().trim().parse().unwrap(), settings.get("length").unwrap().to_string().trim().parse().unwrap()).unwrap();
    if hashpass == true {
        let mut hash = Params::new().hash_length(64).key(password.as_bytes()).personal(b"ksjdh%kajshds$").salt(b"*23#@!@#!@").to_state();
        let mut res = hash.finalize().to_hex();

        let userpass = kdf::Password::from_slice(res.as_bytes()).unwrap();
        let salt = kdf::Salt::from_slice(b"This is an amazing salt lololol").unwrap();
        let key = kdf::derive_key(&userpass , &salt, settings.get("iterations").unwrap().to_string().trim().parse().unwrap(), settings.get("memory").unwrap().to_string().trim().parse().unwrap(), settings.get("length").unwrap().to_string().trim().parse().unwrap()).unwrap();
    }

    

    let mut fileloc = File::create(outfile.trim()).unwrap();
    // let filecontents = read_to_string(infile.trim()).unwrap();
    let mut filecontents = Vec::new();
    let mut file = File::open(infile.trim()).unwrap();
    file.read_to_end(&mut filecontents).unwrap();
    let ciphertext = aead::seal(&key, filecontents.as_ref()).unwrap();

    for i in &ciphertext {
        write!(fileloc , "{},",i);
    }
}

fn guidec(password: String , infile: &String, outfile: &String, hashpass: bool) {

    let jsonfile = match (read_to_string("./config.json")) {
        Ok(T) => T,
        Err(e) => "
        {
            \"twofish\" : {
                \"salt\" : \"This is an amazing salt lololol this can be hover ever long as u want \",
                \"iterations\" : 3,
                \"memory\" : 1024,
                \"length\" : 32
            }
        }
        ".to_string(),
    };
    
    let jsoncontents: serde_json::Value  = serde_json::from_str(&jsonfile.as_str()).unwrap();
    let settings = jsoncontents.get("twofish").unwrap();

    let userpass = kdf::Password::from_slice(password.as_bytes()).unwrap();
    let salt = kdf::Salt::from_slice(settings.get("salt").unwrap().to_string().as_bytes()).unwrap();
    let key = kdf::derive_key(&userpass, &salt,settings.get("iterations").unwrap().to_string().trim().parse().unwrap(), settings.get("memory").unwrap().to_string().trim().parse().unwrap(), settings.get("length").unwrap().to_string().trim().parse().unwrap()).unwrap();

    if (hashpass == true) {
        let mut hash = Params::new().hash_length(64).key(password.as_bytes()).personal(b"ksjdh%kajshds$").salt(b"*23#@!@#!@").to_state();
        let mut res = hash.finalize().to_hex();

        let userpass = kdf::Password::from_slice(res.as_bytes()).unwrap();
        let salt = kdf::Salt::from_slice(b"This is an amazing salt lololol").unwrap();
        let key = kdf::derive_key(&userpass, &salt, settings.get("iterations").unwrap().to_string().trim().parse().unwrap(), settings.get("memory").unwrap().to_string().trim().parse().unwrap(), settings.get("length").unwrap().to_string().trim().parse().unwrap()).unwrap();
    }

    let mut fileloc = File::create(outfile.trim()).unwrap();
    let filecontents = read_to_string(infile.trim()).unwrap();

    // let mut filecontents = Vec::new();
    // let mut file = File::open(infile.trim()).unwrap();
    // file.read_to_end(&mut filecontents).unwrap();

    let mut splitted = filecontents.split(",");

    let mut enctext:Vec<u8> = Vec::new();

    for i in splitted { 
        if i != "" {
            enctext.push(i.trim().parse().unwrap());
        }
    }

    let decipheredtext = aead::open(&key , enctext.as_ref()).unwrap();

    for i in &decipheredtext {
        print!("{}", *i as char);
        write!(fileloc , "{}", *i as char);
    }
}

fn encaes256(password: String , infile : &String, outfile: &String) {

    let jsonfile = match read_to_string("./config.json") {
        Ok(T) => T,
        Err(e) => "
            {
                \"aes256gcmsiv\" : {
                    \"personal\" : \"1$TEl5WXdiaHBCM\",
                    \"salt\" : \"mxjZURQVA$IU3Srw\",
                    \"nonceslice\" : \"GS2x3Yw$5ZXP\"
                }
            }
        ".to_string(),
    };

    let jsoncontents: serde_json::Value = serde_json::from_str(jsonfile.as_str()).unwrap();
    let settings = jsoncontents.get("aes256gcmsiv").unwrap();

    

    let mut hash = Params::new().hash_length(16).key(password.as_bytes()).personal(settings.get("personal").unwrap().as_str().unwrap().as_bytes()).salt(settings.get("salt").unwrap().as_str().unwrap().as_bytes()).to_state();
    let res = hash.finalize().to_hex();


    let key = Key::from_slice(res.as_bytes());
    let cipher = Aes256GcmSiv::new(key);

    let mut fileloc = File::create(outfile.trim()).unwrap();
    let mut filecontents = Vec::new();
    let mut file = File::open(infile.trim()).unwrap();
    file.read_to_end(&mut filecontents).unwrap();

    let ciphertext = cipher.encrypt(Nonce::from_slice(settings.get("nonceslice").unwrap().as_str().unwrap().as_bytes()), filecontents.as_ref()).expect("ERROR WHILE ENCRYPTING AES 256 BIT GCM SIV");

    for i in &ciphertext {
        write!(fileloc , "{}", *i as char);
    }

}

fn decaes256(password: String , infile: &String , outfile: &String) {

    let jsonfile = match read_to_string("./config.json") {
        Ok(T) => T,
        Err(e) => "
            {
                \"aes256gcmsiv\" : {
                    \"personal\" : \"1$TEl5WXdiaHBCM\",
                    \"salt\" : \"mxjZURQVA$IU3Srw\",
                    \"nonceslice\" : \"GS2x3Yw$5ZXP\"
                }
            }
        ".to_string(),
    };

    let jsoncontents: serde_json::Value = serde_json::from_str(&jsonfile.as_str()).unwrap();
    let settings = jsoncontents.get("aes256gcmsiv").unwrap();

    let mut hash = Params::new().hash_length(16).key(password.as_bytes()).personal(settings.get("personal").unwrap().as_str().unwrap().as_bytes()).salt(settings.get("salt").unwrap().as_str().unwrap().as_bytes()).to_state();
    let res = hash.finalize().to_hex();

    let key = Key::from_slice(res.as_bytes());
    let cipher = Aes256GcmSiv::new(key);

    let mut fileloc = File::create(outfile.trim()).unwrap();
    let mut filecontents = read_to_string(infile.trim()).unwrap();
    let mut filestuff = Vec::new();
    // let mut splitted = filecontents.split(",");
    for i in filecontents.chars() {
            filestuff.push(i as u8);
    }
    let mut file = File::open(infile.trim()).unwrap();

    let decipheredtext = cipher.decrypt(Nonce::from_slice(settings.get("nonceslice").unwrap().as_str().unwrap().as_bytes()), filestuff.as_ref()).unwrap();

    for i in &decipheredtext {
        write!(fileloc , "{}", *i as char).unwrap();
    }
}
