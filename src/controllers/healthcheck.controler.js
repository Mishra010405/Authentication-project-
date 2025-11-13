import {APIresponse} from "../utils/api-response.js"
import { asynchandler } from "../utils/async-handler.js";

// const healthcheck = async (req, res, next) => {
//     try {
//         res
//         .status(200)
//         .json(new APIresponse(200,{message : "Server is running"}));
//     }catch (error) {
//         next(err);
//         console.error("Error: ", error);
//     }
// };


const healthcheck = asynchandler(async (req,res) => {
    res.status(200).json(new APIresponse(200,{message : "Server is  running by deeps Mithe brother of Baniya"}));

})
export {healthcheck};