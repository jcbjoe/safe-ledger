/*
  Author: Edward Seufert - Cborgtech, LLC
*/

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const encryption = require('../../encryption');
const logger = require('../../logger');
const settingsManager = require('./settingsManager');
const myCryptKey = crypto.createHmac('sha256','siENFn34783w').update('73fnfisv734e').digest();

const logError = (err) => { err && console.error(err) }

exports.readInstallCodeFile = (vaultFile, myCryptKey) => {
  return new Promise((resolve,reject) => {
    fs.readFile(vaultFile, 'utf-8', (err, data) => {
      if(err){
        reject("Could not read file");
      } else {
        const result = encryption.decrypt(myCryptKey, data);
        let x = JSON.parse(result);
        resolve(x);
      }
    });
  });
};


exports.checkInstallCode = (installCodeDir) => {
  return new Promise((resolve,reject) => {
    const installCodeFile = path.join(installCodeDir, 'installcode.json');
    const settingsFile = path.join(installCodeDir, 'settings.json');
    fs.stat(installCodeDir, (err, stats) => {
      if (err && err.code !== 'ENOENT') {
        reject({status:"ERROR",statusMsg:"Directory or Permission issue"});
      } else if (err || !stats.isDirectory()) {
        // directory does not exist create it
        fs.mkdir(installCodeDir, (err, mkdirData) => {
          // create inital file
          const initCode = encryption.encrypt(myCryptKey, JSON.stringify({key:'init'}));
          fs.writeFile(installCodeFile, initCode, (err, data) => {
            if(err){
              reject({status:ERROR,statusMsg:"Could not save initial install code file"});
            } else {
              // get stats of file to create install code
              fs.stat(installCodeFile, (err, stats) => {
                if (err) {
                  // console.log("error");
                  reject({status:"ERROR",statusMsg:err});
                } else {
                  // create install code
                  const atimeMS = new Date(stats["atime"]).getTime();
                  const upperBound = atimeMS + 10000;
                  const lowerBound = atimeMS - 10000;
                  const initialCode = JSON.stringify({atime:atimeMS,upper:upperBound,lower:lowerBound});
                  const keyCode = encryption.encrypt(myCryptKey, initialCode);
                  logger.writeToLog("InstallCodeManager:: initial key " + initialCode + "\n crypt key "+ keyCode + "\n atime " + stats["atime"]);
                  resolve({status:"ERROR",keyCode,initialCode});
                }
              });
            }
          });
        });
      } else {
        // directory exists now check if file exists
        if (!fs.existsSync(installCodeFile)) {
          // file does not exist create it
          const initCode = encryption.encrypt(myCryptKey, JSON.stringify({key:'init'}));
          fs.writeFile(installCodeFile, initCode, (err, data) => {
            if(err){
              reject({status:ERROR,statusMsg:"Could not save initial install code file"});
            } else {
              // create install code
              const atimeMS = new Date(stats["atime"]).getTime();
              const upperBound = atimeMS + 10000;
              const lowerBound = atimeMS - 10000;
              const initialCode = JSON.stringify({atime:atimeMS,upper:upperBound,lower:lowerBound});
              const keyCode = encryption.encrypt(myCryptKey, initialCode);
              logger.writeToLog("InstallCodeManager:: initial key " + initialCode + "\n crypt key "+ keyCode + "\n atime " + stats["atime"]);
              resolve({status:"ERROR",keyCode,initialCode});
            }
          });
        } else {
          settingsManager.getSettings(installCodeDir)
          .then((settingsVal) => {
            fs.stat(installCodeFile, (err, stats) => {
              if (err) {
                // console.log("error");
                reject({status:"ERROR",statusMsg:err});
              } else {
                // decrypt and compare install code key
                let x = settingsVal.settings;
                const atimeMS = new Date(stats["atime"]).getTime();
                logger.writeToLog("InstallCodeManager:: birth " + stats["birthtime"] + "\n" + "atime " + stats["atime"] + "\n" + "ams " + atimeMS + "\n" + "upper " + x.upper + "\n" + "lower " + x.lower);

                if (x.atime != null && atimeMS <= x.upper && atimeMS >= x.lower ){
                  resolve({status:"SUCCESS"});
                } else {
                  const upperBound = atimeMS + 10000;
                  const lowerBound = atimeMS - 10000;
                  const initialCode = JSON.stringify({atime:atimeMS,upper:upperBound,lower:lowerBound});
                  const keyCode = encryption.encrypt(myCryptKey,initialCode);
                  resolve({status:"ERROR",keyCode,initialCode});
                }
              }
            });
          })
          .catch((val) => {reject(val);});
        }
      }
    });
  });
};

exports.saveInstallCode = (installCodeFile, jsonString) => {
  return new Promise((resolve,reject) => {

    // encrypt here
    const result = encryption.encrypt(myCryptKey, jsonString);
    // save file
    fs.writeFile(installCodeFile, result, (err, data) => {
      if(err){
        reject({status:"ERROR",statusMsg:"Could not save install code file"});
      } else {
        resolve({status:"SUCCESS",statusMsg:"Install code saved"});
      }
    });
  });
};


exports.getInstallCode = (data) => {
  return crypto.createHmac('sha256','siENFn34783w').update(data).digest('hex');
};

exports.scrubInstallCode = (installCodeDir) => {
  return new Promise((resolve,reject) => {
    const installCodeFile = path.join(installCodeDir, 'installcode.json');
    fs.readFile(installCodeFile, 'utf-8', (err, data) => {
      if(err){
        reject({status:"ERROR",statusMsg:"Could not read install code file"});
      } else {
        const decryptResult = encryption.decrypt(myCryptKey, data);
        let x = JSON.parse(decryptResult);
        x.fileCode = "xxx";
        const encryptResult = encryption.encrypt(myCryptKey, JSON.stringify(x));
        fs.writeFile(installCodeFile, encryptResult, (err, data) => {
          if(err){
            reject({status:"ERROR",statusMsg:"Could not save install code file"});
          } else {
            resolve({status:"SUCCESS",statusMsg:"Activation code destroyed"});
          }
        });
      }
    });
  });
}