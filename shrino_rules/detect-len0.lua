function init (args)
    local needs = {}
    needs["http.response_headers.raw"] = tostring(true)
    return needs
end

function match(args)
    local headers = tostring(args["http.response_headers.raw"])
    if string.find(headers, "Length: 0") then
      return 1
    end

    return 0
end