package main //importar os pacotes necessarios para funcionar o programa

import (
	"bytes" // para decifrar o corpo da requisição que vem em numeros e letras
	"crypto/md5" // para criar a assinatura da senha
	"crypto/tls" // para garantir a segurança da requisição
	"encoding/hex" // para decodificar e codificar dados em hexadecimal
	"encoding/json" // para decodificar e codificar dados em JSON
	"errors" // para lidar com os erros
	"fmt" // para imprimir mensagem no terminal
	"io" // para ler o corpo da requisição 
	"net/http" // fazer e receber requisiçoes em HTTP
	"time" // para lidar com o tempo de espera da requisição 
	
)

type Defense struct { // dados que serão enviados para entrar em contato com o Defense
	Senha       string `json:"signature,omitempty"` // senha
	Usuario     string `json:"userName"` // usuario
	Realm       string `json:"realm,omitempty"` // indica ao sistema onde verificar o login do usuario, qual banco de dados ele vai procurar o usuario
	RandomKey   string `json:"randomKey,omitempty"` // código temporário usado para concluir o login, uma senha temporaria
	PublicKey   string `json:"publicKey,omitempty"`// chave envianda para proteger a senha privada do usuario
	EncryptType string `json:"encryptType,omitempty"`// forma matematica de proteger a senha do usuario
	IpAddress   string `json:"ipAddress"` // ip do cliente que está tentando se conectar ao sistema
	ClientType  string `json:"clientType"`// o que exatamente está tentando se conectar ao sistema
	UserType    string `json:"userType"`// o usuario é um usuario comum ou um administrador do sistema
}

type authorizeResponse struct { // dados recebidos do Defense
	Token       string `json:"token"` 
	Realm       string `json:"realm"`
	RandomKey   string `json:"randomKey"`
	PublicKey   string `json:"publicKey"`
	EncryptType string `json:"encryptType"`
	Signature   string `json:"signature"`
	Error       string `json:"error"`
}

func main() { // função base 
	fmt.Print("Usuário: ") // imprime a mensagem "Usuario:" no terminal
	var usuario string // cria a variavel usuario
	if _, err := fmt.Scan(&usuario); err != nil { // ler o que foi digitado e se der erro, imprime a mensagem de erro
		fmt.Printf("erro ao ler usuário: %v\n", err) // mensagem de erro
		return // encerra essa função 
	}

	fmt.Print("Senha: ") // imprime a mensagem "Senha:" no terminal
	var senha string // cria a variavel senha
	if _, err := fmt.Scan(&senha); err != nil { // ler o que foi escrito e se der erro, retorna a mensagem de erro
		fmt.Printf("erro ao ler senha: %v\n", err) // mensagem de erro
		return // encerra essa função
	}

	token, err := conectarDefense(usuario, senha) // chama a função "conectarDefense" e passa usuario e senha para receber o token
	if err != nil { // se der erro, imprime a mensagem de erro
		fmt.Println(err) // mensagem de erro
		return // encerra essa função
	}

	fmt.Println("Token recebido:", token) // se tudo der certo, imprime "Token recebido:" e entrega o token
}

func hash(texto string) string { // função para receber um texto e retornar outro texto com a assinatura da senha
	soma := md5.Sum([]byte(texto)) // faz a soma do texto (numeros e letras) 
	return hex.EncodeToString(soma[:]) // retorna o texto com a assinatura da senha
}

func criarAssinatura(usuario, senha, realm, randomKey string) string { // criar a assinatura da senha do usuario
	senhaHash := hash(senha) // cria a senha 
	senhaHash = hash(usuario + senhaHash) // junta o usuario + senha e cria a assinatura da senha
	senhaHash = hash(senhaHash) // cria a nova assinatura da senha
	senhaHash = hash(usuario + ":" + realm + ":" + senhaHash) // faz com que a assinatura da senha seja única do usuario
	return hash(senhaHash + ":" + randomKey)// cria a assinatura final da senha do usuario
}

func conectarDefense(usuario, senha string) (string, error) { // função para conectar ao Defense e receber o token
	const endpoint = "https://10.100.61.76/brms/api/v1.0/accounts/authorize" // endereço do Defense para conectar 

	desafio := Defense{ // dados que serão enviados para o Defense e assim receber o desafio (os dados que o Defebse envia)
		Usuario:    usuario, // usuario
		IpAddress:  "", // ip do cliente
		ClientType: "WINPC_V2", // tipo de cliente
		UserType:   "0", // tipo de usuario (comum ou administrador)
	}

	primeira, err := postJSON(endpoint, desafio, false) // enviar os dados da função "conectarDefense" para o Defense e receber o desafio
	if err != nil { // se der erro, retorna a mensagem de erro
		return "", fmt.Errorf("erro ao solicitar desafio ao Defense: %w", err) // mensagem de erro
	}
	if primeira.Realm == "" || primeira.RandomKey == "" { // se a resposta do Defense estiver incompleta, retorna mensagem de erro
		return "", fmt.Errorf("resposta de desafio inválida: realm ou randomKey ausente") // mensagem de erro
	}

	segunda := Defense{ // segunda requisição para o Defense, agora com a assinatura da senha do usuario(senha privada protegida)
		Senha:       criarAssinatura(usuario, senha, primeira.Realm, primeira.RandomKey),
		Usuario:     usuario,
		Realm:       primeira.Realm,
		RandomKey:   primeira.RandomKey,
		PublicKey:   primeira.PublicKey,
		EncryptType: primeira.EncryptType,
		IpAddress:   "",
		ClientType:  "WINPC_V2",
		UserType:    "0",
	}

	resposta, err := postJSON(endpoint, segunda, true) // enviar os dados da segunda requisição para o Defense e receber o token
	if err != nil { // se der erro, retorna mensagem de erro
		return "", fmt.Errorf("erro ao autenticar no Defense: %w", err) // mensagem de erro
	}
	if resposta.Token == "" { // se a resposta do Defense não tiver o token, retorna mensagem de erro
		return "", fmt.Errorf("autenticação concluída sem token na resposta") // mensagem de erro
	}

	return resposta.Token, nil // se der certo, retorna o token 
}


func postJSON(endpoint string, payload Defense, final bool) (authorizeResponse, error) { // função para enviar os dados (ip, dados da mensagem,usuario e senha) para o Defense
    corpo, err := json.Marshal(payload) // decodificar a mensagem para enviar ao Defense
    if err != nil { //se der erro, retorna a mensagem de erro
        return authorizeResponse{}, fmt.Errorf("erro ao preparar requisição: %w", err) // mensagem de erro
    }

    tlsConfig := &tls.Config{ // segurança da requisição para que não seja recebida por outras pessoas
        MinVersion:         tls.VersionTLS12, // versão do TLS que será usada
        InsecureSkipVerify: true, // ignorar a verificação de segurança (certificado SSL)
    }

    client := &http.Client{ // dados do cliente que está enviando a requisição para o Defense, em HTTP
        Timeout: 15 * time.Second, // tempo de espera da requisição, se o Defense não responder em 15 segundos a requisição será cancelada
        Transport: &http.Transport{ // como será enviada a requisição para o Defense, em HTTP
            TLSClientConfig: tlsConfig, // segurança da requisição
        },
    }

    req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(corpo)) // criar requisição HTTP para enviar dados e criar associação com senha,usuario e ip 
    if err != nil { // se der erro retorna mensagem de erro
        return authorizeResponse{}, fmt.Errorf("erro ao criar requisição: %w", err) // mensagem de erro
    }

    req.Header.Set("Content-Type", "application/json") // tipo de linguagem que será enviado, JSON
    req.Header.Set("Accept", "application/json") // tipe de linguagem que será aceito, JSON

    resp, err := client.Do(req) // resposta do Defense para o cliente
    if err != nil {// se der erro, retorna mensagem de erro
        return authorizeResponse{}, fmt.Errorf("erro de rede: %w", err) // mensagem de erro
    }
    defer resp.Body.Close() // depois que receber a resposta, fecha a conexão com o Defense

    body, err := io.ReadAll(resp.Body) // ler o corpo da resposta do Defense
    if err != nil { // se der erro, retorna mensagem de erro
        return authorizeResponse{}, fmt.Errorf("erro ao ler resposta: %w", err) // mensagem de erro
    }

    
    desafio401 := !final && resp.StatusCode == http.StatusUnauthorized // "desafio401" só é verdadeiro se não estiver no final da resposta e o servidor não proibir o acesso

    if (resp.StatusCode < 200 || resp.StatusCode >= 300) && !desafio401 { // se a resposta do servidor deu erro e não for o "desafio 401"
        return authorizeResponse{}, fmt.Errorf( // se não der, retorna a mensagem de erro
            "Defense retornou HTTP %s: %s", // mensagem de erro
            resp.Status,
            body,
        )
    }

    var resposta authorizeResponse // variavel resposta para receber o acesso

    if err := json.Unmarshal(body, &resposta); err != nil { // se der erro na leitura(ler em JSON) do corpo da resposta envia uma mensagem de erro
        return authorizeResponse{}, fmt.Errorf( // mensagem de erro
            "resposta não é JSON válido: %w",
            err,
        )
    }

    if resposta.Error != "" { // se a resposta do Defense tiver erro, retorna mensagem de erro
        return authorizeResponse{}, errors.New(resposta.Error) // mensagem de erro
    }

    if !final && (resposta.Realm == "" || resposta.RandomKey == "") { //se na resposta do Defense nao tiver o realm ou randomKey, retorna mensagem de erro
         return authorizeResponse{}, fmt.Errorf( // mensagem de erro é "desafio inválido: realm ou randomKey ausente"
            "desafio inválido: realm ou randomKey ausente",
        )
    }

    if final && resposta.Token == "" { // se na resposta final não tiver o token, retorna mensagem de erro
        return authorizeResponse{}, fmt.Errorf( // a mensagem de erro é "autenticação sem token. Resposta: %s"
            "autenticação sem token. Resposta: %s",
            body,
        )
    }

    return resposta, nil // retorna a resposta do Defense
}
