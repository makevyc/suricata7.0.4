function init (args)
    local needs = {}
    needs["http.response_body"] = tostring(true)
    return needs
end

function match(args)
    -- 获取HTTP响应体
    local response_body = tostring(args["http.response_body"])
    -- 检查响应体是否存在
    if response_body ~= nil then
            return 1
    end
    return 0
end
