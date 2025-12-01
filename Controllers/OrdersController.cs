using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Order_Management.Data;
using Order_Management.Models;

namespace Order_Management.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class OrdersController : ControllerBase
    {
        private readonly ApplicationDbContext _context;

     public OrdersController(ApplicationDbContext context)
        {
 _context = context;
    }

        [Authorize]
 [HttpPost]
        public IActionResult CreateOrder(Order order)
    {
      order.UserName = User.Identity.Name;
   order.TotalAmount = order.Quantity * order.UnitPrice;

_context.Orders.Add(order);
    _context.SaveChanges();

        return Ok(new { message = "Order placed successfully", order });
     }

     [Authorize]
        [HttpGet]
     public IActionResult GetAllOrders()
        {
   var userName = User.Identity.Name;
   var orders = _context.Orders.Where(o => o.UserName == userName).ToList();
return Ok(orders);
        }

        [Authorize]
        [HttpGet("{id}")]
 public IActionResult GetOrderById(int id)
      {
          var userName = User.Identity.Name;
            var order = _context.Orders.FirstOrDefault(o => o.Id == id && o.UserName == userName);

   if (order == null)
    return NotFound(new { message = "Order not found or unauthorized" });

            return Ok(order);
     }

   [Authorize]
        [HttpPut("{id}")]
        public IActionResult UpdateOrder(int id, Order updatedOrder)
        {
   var userName = User.Identity.Name;
 var order = _context.Orders.FirstOrDefault(o => o.Id == id && o.UserName == userName);

         if (order == null)
   return NotFound(new { message = "Order not found or unauthorized" });

        order.ProductName = updatedOrder.ProductName;
     order.Quantity = updatedOrder.Quantity;
   order.UnitPrice = updatedOrder.UnitPrice;
  order.TotalAmount = updatedOrder.Quantity * updatedOrder.UnitPrice;

        _context.SaveChanges();

        return Ok(new { message = "Order updated successfully", order });
    }

   [Authorize]
        [HttpDelete("{id}")]
     public IActionResult DeleteOrder(int id)
      {
  var userName = User.Identity.Name;
            var order = _context.Orders.FirstOrDefault(o => o.Id == id && o.UserName == userName);

    if (order == null)
     return NotFound(new { message = "Order not found or unauthorized" });

      _context.Orders.Remove(order);
  _context.SaveChanges();

   return Ok(new { message = "Order deleted successfully" });
     }
    }
}
