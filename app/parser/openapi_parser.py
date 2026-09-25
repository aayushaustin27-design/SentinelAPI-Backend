import json
import yaml
from typing import Dict, Any, List, Tuple
from fastapi import HTTPException
from ..models.security import DiscoveredEndpoint, SpecParseResponse, HttpMethod

def parse_spec_string(spec_content: str) -> Dict[str, Any]:
    """Parse raw JSON or YAML OpenAPI/Swagger string safely."""
    if not spec_content or not spec_content.strip():
        raise HTTPException(status_code=400, detail="OpenAPI specification content is empty.")
    
    cleaned = spec_content.strip()
    
    # Try JSON first
    if cleaned.startswith("{") or cleaned.startswith("["):
        try:
            return json.loads(cleaned)
        except json.JSONDecodeError as e:
            # Maybe it's YAML with curly braces
            try:
                data = yaml.safe_load(cleaned)
                if isinstance(data, dict):
                    return data
            except Exception:
                pass
            raise HTTPException(
                status_code=400,
                detail=f"Invalid JSON specification syntax: {str(e)}"
            )
    
    # Try YAML
    try:
        data = yaml.safe_load(cleaned)
        if not isinstance(data, dict):
            raise HTTPException(
                status_code=400,
                detail="Parsed YAML document does not contain an OpenAPI root dictionary object."
            )
        return data
    except yaml.YAMLError as e:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid YAML specification syntax: {str(e)}"
        )

def extract_endpoints_from_spec(spec: Dict[str, Any]) -> Tuple[SpecParseResponse, List[DiscoveredEndpoint]]:
    """Extract metadata and discovered endpoints from OpenAPI 2.0 / 3.x document."""
    info = spec.get("info", {})
    title = info.get("title", "OpenAPI Specification")
    version = info.get("version", "1.0.0")
    description = info.get("description", "")
    
    servers = []
    if "servers" in spec and isinstance(spec["servers"], list):
        for s in spec["servers"]:
            if isinstance(s, dict) and "url" in s:
                servers.append(s["url"])
            elif isinstance(s, str):
                servers.append(s)
    elif "host" in spec:
        schemes = spec.get("schemes", ["https"])
        base_path = spec.get("basePath", "")
        servers.append(f"{schemes[0]}://{spec['host']}{base_path}")
    
    global_security = spec.get("security", [])
    has_global_security = len(global_security) > 0

    endpoints: List[DiscoveredEndpoint] = []
    paths = spec.get("paths", {})

    valid_methods = {"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"}

    for path, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue
        
        common_parameters = path_item.get("parameters", [])

        for method_key, operation in path_item.items():
            method_upper = method_key.upper()
            if method_upper not in valid_methods:
                continue
            
            if not isinstance(operation, dict):
                continue

            summary = operation.get("summary") or operation.get("description") or f"{method_upper} {path}"
            operation_id = operation.get("operationId")
            tags = operation.get("tags", [])
            
            # Combine common and operation-specific parameters
            combined_params = list(common_parameters) + operation.get("parameters", [])
            
            # Check security requirement
            op_security = operation.get("security")
            auth_required = has_global_security
            schemes: List[str] = []
            
            if op_security is not None:
                auth_required = len(op_security) > 0
                for sec_dict in op_security:
                    schemes.extend(sec_dict.keys())
            elif has_global_security:
                for sec_dict in global_security:
                    schemes.extend(sec_dict.keys())

            endpoints.append(
                DiscoveredEndpoint(
                    path=path,
                    method=method_upper,  # type: ignore
                    summary=summary,
                    operationId=operation_id,
                    parameters=combined_params,
                    authRequired=auth_required,
                    securitySchemes=list(set(schemes)),
                    tags=tags
                )
            )

    response = SpecParseResponse(
        title=title,
        version=version,
        description=description,
        servers=servers,
        totalEndpoints=len(endpoints),
        endpoints=endpoints
    )

    return response, endpoints
