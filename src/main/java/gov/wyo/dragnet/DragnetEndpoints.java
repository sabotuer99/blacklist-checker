package gov.wyo.dragnet;

import com.google.api.server.spi.config.Api;
import com.google.api.server.spi.config.ApiMethod;
import com.google.api.server.spi.config.ApiMethod.HttpMethod;
import com.google.api.server.spi.config.Named;

/**
 * Defines endpoint functions APIs.
 */
@Api(name = "dragnetendpoints", version = "v1",
scopes = {Constants.EMAIL_SCOPE },
        clientIds = {Constants.WEB_CLIENT_ID, Constants.API_EXPLORER_CLIENT_ID },
        description = "API for dragnet endpoints.")

public class DragnetEndpoints {

   // Declare this method as a method available externally through Endpoints
    @ApiMethod(name = "sayHello", path = "sayHello", httpMethod = HttpMethod.GET)
    public HelloClass sayHello() {
        return new HelloClass("Dummy");
    }

}
