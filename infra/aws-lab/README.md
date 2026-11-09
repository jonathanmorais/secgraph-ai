# GraphSec AWS Lab

Ambiente AWS proposital-mente inseguro para popular o grafo com anti-patterns reais.
**Nunca use em produção.** Tudo tagueado com `Ephemeral=true`.

## Pré-requisitos

- `terraform` ≥ 1.5
- credenciais AWS exportadas (`aws configure` ou variáveis `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY`)
- Conta AWS sandbox / isolada

## Subir

```bash
cd infra/aws-lab
terraform init
terraform apply -auto-approve
```

Saída mostra IP da EC2, URL do bucket público, endpoint do RDS (se ativo) etc.

### Com RDS (opcional, mais caro e demora ~10min)

```bash
terraform apply -auto-approve -var create_rds=true
```

## Popular o grafo

Depois do `apply`, com as mesmas credenciais AWS no `.env` do GraphSec:

```bash
cd ../..
docker compose exec backend python -m graphsec.connectors.aws.sync
```

Abra http://localhost:5173 e pergunte no chat:

- "quais buckets S3 estão públicos?"
- "quais usuários IAM não têm MFA?"
- "quais EC2 estão expostas à internet na porta 22?"
- "qual o caminho de ataque até o bucket de dados de clientes?"

## Cenário K8s (containers + CVE + path pod→role)

Com `scenario_k8s=true` (padrão), a EC2 pública vira um nó k3s com workloads de
demo propositalmente vulneráveis e service accounts anotadas com IRSA.

```bash
terraform apply -auto-approve           # sobe EC2 (t3.small) + k3s + workloads
terraform output k8s                    # IP, endpoint :6443, instruções kubeconfig

# pegue o kubeconfig da instância (aguarde ~3min o user-data rodar):
scp ec2-user@<IP>:/home/ec2-user/kubeconfig.yaml ../../backend/kubeconfig.yaml

# sincronize workloads + scan de CVE (Trivy) no grafo:
cd ../..
docker compose exec backend python -m graphsec.connectors.k8s.sync
```

No frontend, clique na EC2 → painel mostra os **containers rodando** e suas
**CVEs**; o botão "Traçar path de privilégio" pinta em verde o caminho
`EC2 → Pod → ServiceAccount → IAMRole → policy → bucket PII`.

Perguntas de chat que funcionam:
- "quais imagens de container têm CVE crítica?"
- "qual container exposto pode acessar dados via service account?"

## Destruir (importante!)

```bash
terraform destroy -auto-approve
```

ou, se usou RDS:

```bash
terraform destroy -auto-approve -var create_rds=true
```

Como backup, todos os recursos têm tag `Project=graphsec-lab` para busca manual no
console caso o state seja perdido.

## Anti-patterns criados

| # | Recurso | Problema |
|---|---------|----------|
| 1 | `*-clientes-*` S3 bucket | Público, sem encryption, com objeto CSV simulado |
| 2 | `*-wide-open` SG | SSH e HTTP de `0.0.0.0/0` |
| 3 | `*-public-ec2` EC2 | Public IP + SG escancarado |
| 4 | `*-ec2-role` instance profile | `s3:*` em `Resource: "*"` (lateral movement) |
| 5 | `*-dev-sem-mfa` IAM user | Sem MFA + policy ampla |
| 6 | `*-wildcard-trust` role | Trust pro root da conta inteira |
| 7 | `*-lambda-role` Lambda | Role separada, demonstra `HAS_POLICY` cross-resource |
| 8 | `*-prod-db` RDS (opt-in) | `publicly_accessible=true`, `storage_encrypted=false` |

## Custo estimado

- EC2 t3.micro: ~USD 0.0104/h (free tier 750h/mês primeiros 12 meses)
- S3: centavos
- RDS db.t3.micro: ~USD 0.017/h se habilitado
- Lambda, IAM, VPC, IGW: USD 0 enquanto ociosos

Rode `terraform destroy` quando terminar.
