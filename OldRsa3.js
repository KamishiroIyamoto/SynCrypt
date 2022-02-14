document.getElementById("enc").onclick = function(){
  do_encrypt();
};
document.getElementById("dec").onclick = function(){
  do_decrypt();
};
document.querySelector("#file").on = function(){
  document.getElementById("span").value = document.querySelector("input[type=file]").files[0].name;
}

function download(data, filename, type) {
    var file = new Blob([data], {type: type});
    if (window.navigator.msSaveOrOpenBlob)
      window.navigator.msSaveOrOpenBlob(file, filename);
    else {
      var a = document.createElement("a"), url = URL.createObjectURL(file);
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      setTimeout(function() {
        document.body.removeChild(a);
        window.URL.revokeObjectURL(url);  
      }, 0); 
    }
  }
  
  function do_encrypt() {
    do_genrsa();
    var rsa = new RSAKey();
    rsa.setPublic(document.rsatest.n.value, document.rsatest.e.value);
  
    let file = document.getElementById("file").files[0];
    let reader = new FileReader();
    reader.readAsArrayBuffer(file);
    reader.onerror = function() {
      console.log(reader.error);
    }
    reader.onload = function() {
      let view = new Uint8Array(reader.result);
      if(view.byteLength <= 500) {
        var t = new Uint8Array(501);
        for(var i = 0; i < 501; i++)
        {
          if(i < view.byteLength-1)
            t[i] = view[i];
          else
            t[i] = 32;
        }
          view = t;
      }
        let arr = new Array();
        let index = 0;
        var res;
        document.rsatest.ciphertext.value = "";
        let temp = "";
        for(let num of view){
            temp += num + " ";
        }
        let strSize = temp.length;
        while(strSize > 500){
          arr.push(temp.slice(index, index + 500));
          index += 500
          strSize -= 500;
        }
        arr.push(temp.slice(index, reader.result.length));
        arr.forEach((element) => {
          res = rsa.encrypt(element);
          if(res) 
            document.rsatest.ciphertext.value = document.rsatest.ciphertext.value + "\n" + linebrk(res, 64);
        });
        download(file.name.split(".").pop() + "\n" + document.rsatest.n.value + "\n" + document.rsatest.d.value +
        document.rsatest.ciphertext.value, file.name.split(".")[0] + ".sc", Text);
    }
  }
  function do_decrypt() {
    let file = document.getElementById("file").files[0];
    let reader = new FileReader();
    reader.readAsText(file);
    reader.onerror = function() {
      console.log(reader.error);
    }
    reader.onload = function() {
      let enterpos = reader.result.indexOf("\n");
      let filetype = reader.result.slice(0, enterpos);
  
      var rsa = new RSAKey();
      var dr = document.rsatest;
      dr.e.value = 3;
      dr.n.value = reader.result.slice(enterpos + 1, enterpos + 16 * 64 + 16);
      enterpos += 16 * 64 + 16;
      dr.d.value = reader.result.slice(enterpos + 1, enterpos + 16 * 64 + 16);
      enterpos += 16 * 64 + 16;
      rsa.setPrivate(dr.n.value, dr.e.value, dr.d.value);
  
      let ave = reader.result.slice(enterpos + 1, reader.result.length);
      var res;
      let counter = 0;
      let buf = "";
      let temp = "";
        let str = ave.split("\n");
        str.forEach((element) => {
          buf = buf + element + "\n";
          counter++;
          if((counter % 16 === 0 && counter != 0) || counter === str.length) {
            res = rsa.decrypt(buf);
            if(res == null) {
              temp = "*** Invalid Ciphertext ***";
              console.log("*** Invalid Ciphertext ***");
            }
            else {
              temp += res;
              buf = "";
            }
          }
        });

      let tarr = temp.split(" ");
      if(tarr[tarr.length - 1] == "" || tarr[tarr.length - 2] == "32" && tarr[tarr.length - 3] == "32")
      {
        let spaseIndex = 0;
        for(var i = tarr.length - 2; i >= 0; i--)
        {
          if(tarr[i] != "32"){
            spaseIndex = i;
            break;
          }
        }
        tarr = tarr.slice(0, spaseIndex + 1);
      }
      let ab = new ArrayBuffer(tarr.length);
      let view = new Uint8Array(ab);
      for(let i = 0; i < tarr.length; i++) {
        view[i] = tarr[i];
      }
      download(ab, file.name.split(".")[0] + "." + filetype, ArrayBuffer);
    }
  }
  
  function do_genrsa() {
    var rsa = new RSAKey();
    var dr = document.rsatest;
    rsa.generate(parseInt(4096),dr.e.value);
    dr.n.value = linebrk(rsa.n.toString(16),64);
    dr.d.value = linebrk(rsa.d.toString(16),64);
  }