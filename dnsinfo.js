var fs = require('fs');
var async = require('async');
var dns = require('dns-axfr');
var EventProxy = require('eventproxy');
var NSlist = [];
var ep = new EventProxy();
var argv = process.argv;
var types = ['A','AAAA','CNAME','MX','SOA','TXT','NS'];


if(argv.length<3){
    console.log("\n\t使用方法: iojs dns.js www.baidu.com\n");
    console.log("\t    Author: 0x_Jin@root@xss1.com\n");
    process.exit();
}
ep.all('A','AAAA','CNAME','MX','SOA','TXT','NS', function (A,AAAA,CNAME,MX,SOA,TXT,NS) {
    console.log("\n=============开始检测域名解析信息===========\n");
    for(i in arguments){
        if(arguments[i].type){
            if(arguments[i].addr.length>1){
                for(x in arguments[i].addr){
                    if(arguments[i].type=="MX"){
                        console.log(arguments[i].type+"\t"+arguments[i].addr[x].exchange);
                    }
                    else if(arguments[i].type=="SOA"){
                        var tmp = "";
                        for(c in arguments[i].addr){
                            tmp += arguments[i].addr[c] + "\t";
                        }
                        console.log(arguments[i].type + "\t" + tmp);
                    }
                    else{
                        console.log(arguments[i].type+"\t"+arguments[i].addr[x]);
                    }
                }
            }
            else{
                if(arguments[i].type=="MX"&&arguments[i].addr!=""){
                    console.log(arguments[i].type+"\t"+arguments[i].addr[0].exchange);
                }
                else if(arguments[i].type=="SOA"){
                    var tmp = "";
                    for(c in arguments[i].addr){
                        tmp += arguments[i].addr[c] + "\t";
                    }
                    console.log(arguments[i].type + "\t" + tmp);
                }
                else {
                    console.log(arguments[i].type + "\t" + arguments[i].addr);
                }
            }
        }
    }
    console.log("\n=============开始检测域传送漏洞=============\n");
    for(x in NSlist){
        dns_info(NSlist[x],argv[argv.length-1]);
    }
});

function dns_info(dns_server,dns_domain){
    dns.resolveAxfr(dns_server, dns_domain, function(err, addr) {
        if (err) {
            console.error('Error ocurred: ' + addr + ' (' + err + ')');
            return;
        }
        else {
            var result = addr.answers;
            for (x in result) {
                var tmp = "";
                for (i in result[x]) {
                    tmp += result[x][i] + "\t";
                }
                console.log(tmp);
            }
            console.log("\n"+dns_server+" Find result : " + result.length+"\n");
            //如果想域传送漏洞信息比较简洁的话就去掉注释
            //process.exit();
            if(result.length){
                fs.appendFile('history.txt', "Dns Server: "+dns_server+" Domain: "+dns_domain+" Result: "+result.length+"\n", function (err) {
                    if (err) {
                        console.log("\nWrite Result To File Error!");
                        throw err;
                    }
                    console.log(dns_server+' Result Save to history.txt\n');
                });
            }
        }
    });
}

function domain_info(target,type){
    dns.resolve(target,type, function(err,address){
        if (err) {
            ep.emit(type,err);
        }
        else{
            if(type=="NS"){
                NSlist = address;
            }
            ep.emit(type, {"type":type,"addr":address});
        }
    })
}
for(x in types){
    domain_info(argv[argv.length-1],types[x]);
}