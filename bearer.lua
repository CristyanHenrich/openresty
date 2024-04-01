local jwt = require "resty.jwt"
local cjson = require "cjson"

local token = ngx.var.arg_token

if token == nil then
    token = ngx.var.cookie_token
end

if token == nil then
    local auth_header = ngx.var.http_Authorization
    if auth_header then
        _, _, token = string.find(auth_header, "Bearer%s+(.+)")
    end
end

if token == nil then
    ngx.status = ngx.HTTP_UNAUTHORIZED
    ngx.header.content_type = "application/json; charset=utf-8"
    ngx.say("{\"error\": \"token JWT ausente ou cabeçalho de autorização\"}")
    ngx.exit(ngx.HTTP_UNAUTHORIZED)
end

local validators = require "resty.jwt-validators"
local claim_spec = {}

local jwt_obj = jwt:verify(os.getenv("JWT_SECRET"), token, claim_spec)

if not jwt_obj["verified"] then
    ngx.status = ngx.HTTP_UNAUTHORIZED
    ngx.log(ngx.WARN, jwt_obj.reason)
    ngx.header.content_type = "application/json; charset=utf-8"
    ngx.say("{\"error\": \"" .. jwt_obj.reason .. "\"}")
    ngx.exit(ngx.HTTP_UNAUTHORIZED)
end

ngx.req.set_header("Authorization", "Bearer " .. token)
ngx.req.set_header("X-IP", jwt_obj.payload.ip)
ngx.req.set_header("X-Socket", jwt_obj.payload.socket)
ngx.req.set_header("X-API", jwt_obj.payload.api)
