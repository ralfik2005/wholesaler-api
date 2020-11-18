const http = require('http');
const dns = require('dns');
const dkim = require('dkim');
const hostname = 'localhost';

var express = require('express');
var app = express();
const multer = require('multer');
const upload = multer();
var server = app.listen(3000);
app.use(express.static('public'));
app.use(function (req, res, next) {

    // Website you wish to allow to connect
    res.setHeader('Access-Control-Allow-Origin', '*');

    // Request methods you wish to allow
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS, PUT, PATCH, DELETE');

    // Request headers you wish to allow
    res.setHeader('Access-Control-Allow-Headers', 'X-Requested-With,content-type');

    // Set to true if you need the website to include cookies in the requests sent
    // to the API (e.g. in case you use sessions)
    res.setHeader('Access-Control-Allow-Credentials', true);

    // Pass to next layer of middleware
    next();
});


app.post('/spfCheck', upload.none(), (req, res) => {
    const formData = req.body;

    dns.resolveTxt(formData.domain, function (err, addresses) {
        if(err==null){
            for(let el of addresses){
                if(el[0].includes("v=spf")){
                  if(el[0].includes("include:stayprivatemail.com")){
                    let str = el[0].split("include:stayprivatemail.com").pop();
                    if(str.includes("+all")||str.includes("~all")||str.includes("-all")){
                        res.status(200).json({
                            data: 'SPF Record looks great!'
                        });
                    }else{
                        res.status(403).json({
                            ErrorMsg: 'Invalid SPF record'
                        });
                    }
                  }else{
                    res.status(403).json({
                        ErrorMsg: 'Cant find include:stayprivatemail.com in SPF record'
                    });
                  }
                }
            }
        }else if(err.code=='ENOTFOUND'){
            res.status(404).json({
                ErrorMsg: 'Email not found'
            });
        }else if(err.code=='ENODATA'){
            res.status(404).json({
                ErrorMsg: 'No SPF record found'
            });
        }else if(err.code=='ESERVFAIL'){
            res.status(503).json({
                ErrorMsg: 'Failed to reach server. Please try again.'
            });
        }
        else{console.log(err)}
        
    });
});

app.post('/dkimCheck', upload.none(), (req, res) => {
    const formData = req.body;    
    dkimDomain = 'stayprivate._domainkey.' + formData.domain;
    dns.resolveTxt(dkimDomain, function (err1, dkim1) {
        if(err1==null){
            dns.resolveTxt("stayprivate._domainkey.stayprivatemail.com", function (err, dkim2) {
                if(err==null){
                    if((dkim1[0][0]+dkim1[0][1])==(dkim2[0][0]+dkim2[0][1])){
                        res.status(200).json({
                            data: 'DKIM Record looks great!'
                        });   
                    }else{
                        res.status(403).json({
                            ErrorMsg: 'DKIM Record does not match'
                        });
                    }
                }else if(err.code=='ENOTFOUND'){
                    res.status(404).json({
                        ErrorMsg: 'Email not found. SP'
                    });
                }else if(err.code=='ENODATA'){
                    res.status(404).json({
                        ErrorMsg: 'No DKIM Record found. SP'
                    });
                }else if(err.code=='ESERVFAIL'){
                    res.status(503).json({
                        ErrorMsg: 'Failed to reach server. Please try again. SP'
                    });
                }
                else{console.log(err1)}
                
            });
        }else if(err1.code=='ENOTFOUND'){
            res.status(404).json({
                ErrorMsg: 'Email not found'
            });
        }else if(err1.code=='ENODATA'){
            res.status(404).json({
                ErrorMsg: 'No DKIM Record found'
            });
        }else if(err1.code=='ESERVFAIL'){
            res.status(503).json({
                ErrorMsg: 'Failed to reach server. Please try again.'
            });
        }
        else{console.log(err1)}
    });
});