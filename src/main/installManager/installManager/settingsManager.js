/*
  Author: Edward Seufert - Cborgtech, LLC
*/

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const encryption = require('../../encryption');
const logger = require('../../logger.js');
const myCryptKey = crypto.createHmac('sha256','cfWDFn25486x').update('59GHwlps47e6').digest();

const logError = (err) => { err && console.error(err) }

exports.loadSettings = (installCodeDir) => {
  return new Promise((resolve,reject) => {
    const settingsFile = path.join(installCodeDir, 'settings.json');
    const initSettings = {
      numFailAttempts:5,
      numLockoutRetries:3,
      minutesToWaitBetweenLockout:15,
      scrubInstallAfterRetries:false,
      scrubContentAfterRetries:true,
      failAttemptCount:0,
      lockLogin:false,
      lockOutCount:0
    }
    fs.stat(installCodeDir, (err, stats) => {
      if (err && err.code !== 'ENOENT') {
        reject({status:"ERROR",statusMsg:"Directory or Permission issue"});
      } else if (err || !stats.isDirectory()) {
        fs.mkdir(installCodeDir, (err, mkdirData) => {
          // encrypt here
          const result = encryption.encrypt(myCryptKey, JSON.stringify(initSettings));
          // save file
          fs.writeFile(settingsFile, result, (werr, wdata) => {
            //console.log("Error " + err);
              if(werr){
                reject({status:"ERROR",statusMsg:"Init Settings Failed"});
              } else {
                resolve({status:"SUCCESS",settings:initSettings});
              }
          });
        });
      } else {
        if (!fs.existsSync(settingsFile)) {
          // encrypt here
          const result = encryption.encrypt(myCryptKey, JSON.stringify(initSettings));
          // save file
          fs.writeFile(settingsFile, result, (werr, wdata) => {
            //console.log("Error " + err);
              if(werr){
                reject({status:"ERROR",statusMsg:"Init Settings Failed"});
              } else {
                resolve({status:"SUCCESS",settings:initSettings});
              }
          });
        } else {
          // console.log("load settings");
          fs.readFile(settingsFile, 'utf-8', (err, data) => {
              // decrypt
              const result = encryption.decrypt(myCryptKey, data);
              let x = JSON.parse(result);
              resolve({status:"SUCCESS",settings:x});
          });
        }
      }
    });
  });
}

exports.getSettings = (basePath) => {
  return new Promise((resolve,reject) => {
    fs.readFile(path.join(basePath, "settings.json"), 'utf-8', (err, data) => {
      if(err){
        reject({status:"ERROR",statusMsg:"Could not read settings file"});
      } else {
        // decrypt here
        try {
          const result = encryption.decrypt(myCryptKey, data);
          let x = JSON.parse(result);
            resolve({status:"SUCCESS",settings:x});
        } catch (err) {
          reject({status:"ERROR",statusMsg:"Encryption error"});
        }
      }
    });
  });
}

exports.saveSettings = (basePath,settings) => {
  return new Promise((resolve,reject) => {
    // save file
    //console.log("Save settings " + JSON.stringify(settings));
    const result = encryption.encrypt(myCryptKey, JSON.stringify(settings));
    fs.writeFile(path.join(basePath, "settings.json"), result, (err, data) => {
      //console.log("Error " + err);
        if(err){
          reject({status:"ERROR",statusMsg:"Settings save failed"});
        } else {
          resolve({status:"SUCCESS"});
        }
    });
  });
}

exports.checkLoginAttempts = (basePath) => {
  return new Promise((resolve,reject) => {
    fs.readFile(path.join(basePath, "history.json"), 'utf-8', (err, data) => {
      if(err){
        reject({status:"ERROR",statusMsg:"Could not read history file"});
      } else {
        // decrypt here
        try {
        //  const result = encryption.decrypt(myCryptKey, data);
          let x = JSON.parse(data);
          let current = new Date().getTime();
          let diff = x.time - current;
          if (diff > 86400){
            resolve({status:"SUCCESS"});
          } else {
            reject({status:"ERROR",statusMsg:"Password lock active try again after 24 hours"});
          }
        } catch (err) {
          reject({status:"ERROR",statusMsg:"Invalid Password"});
        }
      }
    });
  });
}