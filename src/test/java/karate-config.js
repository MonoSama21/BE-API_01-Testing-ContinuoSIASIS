function fn() {
  var env = karate.env || 'QA';
  karate.log('Ejecución de pruebas en ambiente de:', env);

  var ENV = {
    DEV: {
      api: {
        urlBase: "URL"
      }
    },
    QA: {
      api: {
        urlBase: "https://api01-siasis-cert.vercel.app"
      }
    }
  };

  var envConfig = ENV[env] || ENVIRONMENTS.DEV;
  karate.log('Ambiente cargado:', env);

  //CONSTRUYENDO AMBIENTE
  function configEnv(){
    try{
      return{
        urlBase: envConfig.api.urlBase,

        headers: {

        }
      }
    } catch (error){
      throw new Error("Error construyendo ambiente")
    }
  }

  var statusEnv = configEnv();
  karate.configure('connectTimeout', 5000);
	karate.configure('readTimeout', 5000);
  return statusEnv;
}